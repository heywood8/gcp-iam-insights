package analyzer

import (
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

// PrivilegeConfig holds configuration for the privilege analyzer.
type PrivilegeConfig struct {
	Registry           roles.Registry
	SuggestCustomRoles bool
	Project            string // used in generated gcloud commands
}

// AnalyzePrivilege returns privilege findings for a single ServiceAccountReport.
func AnalyzePrivilege(report ServiceAccountReport, cfg PrivilegeConfig) []Finding {
	var findings []Finding

	// 1. Flag primitive roles immediately.
	for _, role := range report.Roles {
		if primitiveRoles[role] {
			findings = append(findings, Finding{
				ServiceAccount: report.Email,
				Severity:       SeverityCritical,
				Type:           FindingTypePrimitiveRole,
				Message:        fmt.Sprintf("service account has primitive role %s — always too broad", role),
				Remediation:    fmt.Sprintf("replace %s with a predefined or custom role scoped to actual API usage", role),
				Details:        map[string]string{"role": role},
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
					Remediation: fmt.Sprintf("delete unused key %s — it is an unnecessary credential with no operational use", key.KeyID),
					Details: map[string]string{
						"key_id":       key.KeyID,
						"key_age_days": fmt.Sprintf("%d", ageDays),
					},
				})
			}
		}
	}

	// 3. If no exercised permissions — can't suggest role replacements.
	if len(report.ExercisedPerms) == 0 {
		return findings
	}

	// 4. Find minimal covering set of predefined roles.
	suggested, uncovered := cfg.Registry.FindMinimalRoles(report.ExercisedPerms)

	// 5. If current roles grant no more permissions than the exercised set, no over-privilege finding.
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
	remediation := fmt.Sprintf("rebind to: %s", strings.Join(suggested, ", "))
	if cfg.SuggestCustomRoles {
		msg = fmt.Sprintf("service account has broader permissions than it uses; suggested custom role permissions: %s", strings.Join(report.ExercisedPerms, ", "))
		remediation = fmt.Sprintf("create a custom role with only: %s", strings.Join(report.ExercisedPerms, ", "))
	}

	findings = append(findings, Finding{
		ServiceAccount: report.Email,
		Severity:       SeverityWarn,
		Type:           FindingTypeOverPrivilege,
		Message:        msg,
		Remediation:    remediation,
		Details:        details,
	})

	return findings
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

