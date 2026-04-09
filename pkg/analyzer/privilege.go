package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/roles"
)

var primitiveRoles = map[string]bool{
	"roles/owner":  true,
	"roles/editor": true,
	"roles/viewer": true,
}

// CatalogClient fetches IAM role and permission data from an external catalog.
type CatalogClient interface {
	RolesForPermission(ctx context.Context, perm string) ([]string, error)
	PermissionsForRole(ctx context.Context, role string) ([]string, error)
}

// PrivilegeConfig holds configuration for the privilege analyzer.
type PrivilegeConfig struct {
	Registry           roles.Registry
	SuggestCustomRoles bool
	Project            string // used in generated gcloud commands
	Catalog            CatalogClient
}

// AnalyzePrivilege returns privilege findings for a single ServiceAccountReport.
// It handles primitive role detection, unused key detection, and (when Catalog is
// nil) registry-based over-privilege detection. Catalog-based over-privilege
// detection is handled by AnalyzeCatalogPrivilege.
func AnalyzePrivilege(report ServiceAccountReport, cfg PrivilegeConfig) []Finding {
	var findings []Finding
	links := GenerateConsoleLinks(cfg.Project, report.Email, report.LookbackWindow)

	// 1. Flag primitive roles immediately.
	for _, role := range report.Roles {
		if primitiveRoles[role] {
			findings = append(findings, Finding{
				ServiceAccount: report.Email,
				Severity:       SeverityCritical,
				Type:           FindingTypePrimitiveRole,
				Message:        fmt.Sprintf("service account has primitive role %s — always too broad", role),
				Remediation:    fmt.Sprintf("replace %s with narrower role", role),
				Details:        map[string]string{"role": role},
				Links:          links,
			})
		}
	}

	// 2. Check for unused keys — only when the SA itself is active.
	saIsActive := len(report.ActiveAPIs) > 0
	if saIsActive {
		for _, key := range report.Keys {
			if key.AuthnEvents == 0 {
				ageDays := int(time.Since(key.CreateTime).Hours() / 24)
				findings = append(findings, Finding{
					ServiceAccount: report.Email,
					Severity:       SeverityWarn,
					Type:           FindingTypeUnusedKey,
					Message: fmt.Sprintf(
						"key %s has no authentication traffic but the service account is active (key age: %d days)",
						key.KeyID, ageDays,
					),
					Remediation: fmt.Sprintf("delete unused key %s", key.KeyID),
					Details: map[string]string{
						"key_id":       key.KeyID,
						"key_age_days": fmt.Sprintf("%d", ageDays),
					},
					Links: links,
				})
			}
		}
	}

	// 3. If a catalog client is provided, over-privilege detection is handled
	// by AnalyzeCatalogPrivilege. Skip the registry-based fallback.
	if cfg.Catalog != nil {
		return findings
	}

	// 4. If no exercised permissions — can't suggest role replacements.
	if len(report.ExercisedPerms) == 0 {
		return findings
	}

	// 5. Find minimal covering set of predefined roles (registry-based fallback).
	suggested, uncovered := cfg.Registry.FindMinimalRoles(report.ExercisedPerms)

	// 6. If current roles grant no more permissions than the exercised set, no over-privilege finding.
	if !hasExcessPermissions(report.Roles, report.ExercisedPerms, cfg.Registry) {
		return findings
	}

	details := map[string]string{
		"current_roles": strings.Join(report.Roles, ", "),
	}

	if cfg.SuggestCustomRoles {
		details["custom_role_permissions"] = strings.Join(report.ExercisedPerms, ", ")
		details["gcloud_command"] = fmt.Sprintf(
			"gcloud iam roles create custom_%s --project=%s --permissions=%s --stage=GA",
			sanitizeRoleName(report.Email),
			cfg.Project,
			strings.Join(report.ExercisedPerms, ","),
		)
		details["note"] = "Custom role based on audit logs; may be under-scoped if audit logging is incomplete"
	} else {
		details["suggested_roles"] = strings.Join(suggested, ", ")
	}

	if len(uncovered) > 0 {
		details["uncovered_permissions"] = strings.Join(uncovered, ", ")
	}

	msg := fmt.Sprintf("service account has broader permissions than it uses; suggest: %s", strings.Join(suggested, ", "))
	remediation := strings.Join(suggested, ", ")
	if cfg.SuggestCustomRoles {
		msg = fmt.Sprintf("service account has broader permissions than it uses; suggested custom role permissions: %s", strings.Join(report.ExercisedPerms, ", "))
		remediation = fmt.Sprintf("custom role: %s", strings.Join(report.ExercisedPerms, ", "))
	}

	findings = append(findings, Finding{
		ServiceAccount: report.Email,
		Severity:       SeverityWarn,
		Type:           FindingTypeOverPrivilege,
		Message:        msg,
		Remediation:    remediation,
		Details:        details,
		Links:          links,
	})

	return findings
}

// AnalyzeCatalogPrivilege detects over-privilege using the catalog client.
// It is a no-op if cfg.Catalog is nil or the SA has no exercised permissions.
//
// Algorithm:
//  1. For each exercised permission, fetch the roles that include it.
//  2. Union all candidate roles into a pool.
//  3. Fetch the full permission set for each candidate role.
//  4. Greedy set cover to find the minimal roles covering all exercised permissions.
//  5. If the current roles grant more than the exercised set, emit a finding.
func AnalyzeCatalogPrivilege(ctx context.Context, report ServiceAccountReport, cfg PrivilegeConfig) ([]Finding, error) {
	if cfg.Catalog == nil || len(report.ExercisedPerms) == 0 {
		return nil, nil
	}

	links := GenerateConsoleLinks(cfg.Project, report.Email, report.LookbackWindow)

	// Step 1+2: collect candidate roles from all exercised permission pages.
	candidateSet := make(map[string]bool)
	for _, perm := range report.ExercisedPerms {
		rolesForPerm, err := cfg.Catalog.RolesForPermission(ctx, perm)
		if err != nil {
			// soft skip — this permission's candidates are excluded
			continue
		}
		for _, r := range rolesForPerm {
			candidateSet[r] = true
		}
	}
	if len(candidateSet) == 0 {
		return nil, nil
	}

	// Step 3: fetch permission sets for all candidates.
	candidatePerms := make(map[string][]string, len(candidateSet))
	for role := range candidateSet {
		perms, err := cfg.Catalog.PermissionsForRole(ctx, role)
		if err != nil {
			continue // skip roles we can't fetch
		}
		candidatePerms[role] = perms
	}
	if len(candidatePerms) == 0 {
		return nil, nil
	}

	// Step 4: greedy set cover over candidate roles.
	reg := roles.Registry(candidatePerms)
	suggested, _ := reg.FindMinimalRoles(report.ExercisedPerms)
	if len(suggested) == 0 {
		return nil, nil
	}

	// Step 5: check whether current roles grant permissions beyond what was exercised.
	// Fetch permissions for current roles that weren't already in the candidate pool.
	currentPerms := make(map[string][]string, len(report.Roles))
	for _, role := range report.Roles {
		if perms, ok := candidatePerms[role]; ok {
			currentPerms[role] = perms
		} else {
			// current role not in candidates (e.g. a broader role) — fetch it
			perms, err := cfg.Catalog.PermissionsForRole(ctx, role)
			if err == nil {
				currentPerms[role] = perms
			}
		}
	}

	if !hasExcessPermissionsMap(report.Roles, report.ExercisedPerms, currentPerms) {
		return nil, nil
	}

	details := map[string]string{
		"current_roles":   strings.Join(report.Roles, ", "),
		"suggested_roles": strings.Join(suggested, ", "),
	}

	return []Finding{{
		ServiceAccount: report.Email,
		Severity:       SeverityWarn,
		Type:           FindingTypeOverPrivilege,
		Message: fmt.Sprintf(
			"service account has broader permissions than it uses (%d exercised); suggest: %s",
			len(report.ExercisedPerms), strings.Join(suggested, ", "),
		),
		Remediation: strings.Join(suggested, ", "),
		Details:     details,
		Links:       links,
	}}, nil
}

// hasExcessPermissionsMap returns true when the permissions granted by the current
// roles (looked up in rolePerms) are a strict superset of the exercised permissions.
func hasExcessPermissionsMap(currentRoles []string, exercisedPerms []string, rolePerms map[string][]string) bool {
	exercised := make(map[string]bool, len(exercisedPerms))
	for _, p := range exercisedPerms {
		exercised[p] = true
	}
	for _, role := range currentRoles {
		for _, perm := range rolePerms[role] {
			if !exercised[perm] {
				return true
			}
		}
	}
	return false
}

// hasExcessPermissions returns true when the permissions granted by the current
// roles are a strict superset of the exercised permissions. If the current
// roles grant only what was exercised (or less), there is no over-privilege.
func hasExcessPermissions(currentRoles []string, exercisedPerms []string, reg roles.Registry) bool {
	exercised := make(map[string]bool, len(exercisedPerms))
	for _, p := range exercisedPerms {
		exercised[p] = true
	}
	for _, role := range currentRoles {
		for _, perm := range reg[role] {
			if !exercised[perm] {
				return true
			}
		}
	}
	return false
}

// sanitizeRoleName converts a SA email into a valid custom role name component.
func sanitizeRoleName(email string) string {
	name := strings.SplitN(email, "@", 2)[0]
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	result := sb.String()
	if len(result) > 30 {
		result = result[:30]
	}
	return result
}
