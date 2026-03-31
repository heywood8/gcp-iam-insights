package analyzer

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/gcp"
)

// BuildConfig holds all dependencies needed to build ServiceAccountReports.
type BuildConfig struct {
	Project              string
	LookbackWindow       time.Duration
	ServiceAccountFilter string // if set, only analyze this SA email

	IAM        gcp.IAMClient
	Asset      gcp.AssetClient
	Logging    gcp.LoggingClient
	Monitoring gcp.MonitoringClient
}

// BuildReports fetches data from all GCP sources and constructs a
// ServiceAccountReport for each service account in the project.
func BuildReports(ctx context.Context, cfg BuildConfig) ([]ServiceAccountReport, error) {
	// 1. List service accounts.
	sas, err := cfg.IAM.ListServiceAccounts(ctx, cfg.Project)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}

	// 2. Get project-level IAM bindings + inherited bindings from Asset Inventory.
	projectBindings, err := cfg.IAM.ListProjectBindings(ctx, cfg.Project)
	if err != nil {
		return nil, fmt.Errorf("list project bindings: %w", err)
	}
	assetBindings, err := cfg.Asset.SearchIAMPolicies(ctx, cfg.Project)
	if err != nil {
		return nil, fmt.Errorf("search asset IAM policies: %w", err)
	}
	allBindings := make([]gcp.ProjectBinding, 0, len(projectBindings)+len(assetBindings))
	allBindings = append(allBindings, projectBindings...)
	allBindings = append(allBindings, assetBindings...)

	// Build a map from SA email → set of bound roles.
	rolesBySA := map[string]map[string]bool{}
	for _, b := range allBindings {
		for _, member := range b.Members {
			email := member
			const prefix = "serviceAccount:"
			if len(member) > len(prefix) && member[:len(prefix)] == prefix {
				email = member[len(prefix):]
			}
			if rolesBySA[email] == nil {
				rolesBySA[email] = map[string]bool{}
			}
			rolesBySA[email][b.Role] = true
		}
	}

	since := time.Now().Add(-cfg.LookbackWindow)
	var reports []ServiceAccountReport

	for _, sa := range sas {
		if cfg.ServiceAccountFilter != "" && sa.Email != cfg.ServiceAccountFilter {
			continue
		}

		// 3. Collect bound roles.
		var roles []string
		for role := range rolesBySA[sa.Email] {
			roles = append(roles, role)
		}

		// 4. Fetch SA keys.
		gcpKeys, err := cfg.IAM.ListServiceAccountKeys(ctx, cfg.Project, sa.Email)
		if err != nil {
			return nil, fmt.Errorf("list keys for %s: %w", sa.Email, err)
		}

		// 5. Fetch Cloud Monitoring metrics (non-fatal: log warnings and continue with empty data).
		activeAPIs := map[string]int64{}
		if apis, err := cfg.Monitoring.GetRequestCountPerAPI(ctx, cfg.Project, sa.UniqueID, since); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not fetch request count metrics for %s: %v\n", sa.Email, err)
		} else {
			activeAPIs = apis
		}

		authnPerKey := map[string]int64{}
		if authn, err := cfg.Monitoring.GetAuthnEventsPerKey(ctx, cfg.Project, sa.UniqueID, since); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not fetch authn event metrics for %s: %v\n", sa.Email, err)
		} else {
			authnPerKey = authn
		}

		// Merge authn events into keys.
		saKeys := make([]SAKey, 0, len(gcpKeys))
		for _, k := range gcpKeys {
			saKeys = append(saKeys, SAKey{
				KeyID:       k.KeyID,
				CreateTime:  k.CreateTime,
				AuthnEvents: authnPerKey[k.KeyID],
			})
		}

		// 6. Fetch audit logs (non-fatal: log warning and continue with empty data).
		var logEntries []gcp.AuditEntry
		if entries, err := cfg.Logging.QueryAuditLogs(ctx, cfg.Project, sa.Email, since); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not query audit logs for %s: %v\n", sa.Email, err)
		} else {
			logEntries = entries
		}

		// Deduplicate exercised permissions and find APIs with no log coverage.
		permSet := map[string]bool{}
		loggedAPIs := map[string]bool{}
		var latestLog *time.Time
		for _, entry := range logEntries {
			if entry.MethodName != "" {
				permSet[entry.MethodName] = true
			}
			if entry.ServiceName != "" {
				loggedAPIs[entry.ServiceName] = true
			}
			t := entry.Timestamp
			if latestLog == nil || t.After(*latestLog) {
				latestLog = &t
			}
		}

		var exercisedPerms []string
		for p := range permSet {
			exercisedPerms = append(exercisedPerms, p)
		}

		// APIs active in metrics but absent from audit logs.
		var sparseAPIs []string
		for api, count := range activeAPIs {
			if count > 0 && !loggedAPIs[api] {
				sparseAPIs = append(sparseAPIs, api)
			}
		}

		// Determine LastUsed: prefer audit log timestamp — it's the most precise signal (actual call time).
		// Metrics fallback: if APIs were active within the window but no audit log captured a timestamp.
		var lastUsed *time.Time
		if latestLog != nil {
			lastUsed = latestLog
		}
		if lastUsed == nil && len(activeAPIs) > 0 {
			now := time.Now()
			lastUsed = &now
		}

		reports = append(reports, ServiceAccountReport{
			Email:          sa.Email,
			UniqueID:       sa.UniqueID,
			DisplayName:    sa.DisplayName,
			Roles:          roles,
			Keys:           saKeys,
			ActiveAPIs:     activeAPIs,
			ExercisedPerms: exercisedPerms,
			SparseAPIs:     sparseAPIs,
			LastUsed:       lastUsed,
			LookbackWindow: cfg.LookbackWindow,
		})
	}

	return reports, nil
}
