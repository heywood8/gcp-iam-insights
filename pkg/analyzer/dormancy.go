package analyzer

import (
	"fmt"
	"strings"
	"time"
)

// DormancyConfig holds threshold configuration for the dormancy analyzer.
type DormancyConfig struct {
	Project      string
	WarnDays     int
	CriticalDays int
}

// isDefaultGCPServiceAccount returns true for system-managed service accounts
// that are created by default and may legitimately never be used.
func isDefaultGCPServiceAccount(email string) bool {
	// App Engine default service account: <project>@appspot.gserviceaccount.com
	if strings.HasSuffix(email, "@appspot.gserviceaccount.com") {
		return true
	}
	// Compute Engine default service account: <project-number>-compute@developer.gserviceaccount.com
	if strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") {
		return true
	}
	return false
}

// AnalyzeDormancy returns dormancy findings for a single ServiceAccountReport.
// It uses LastUsed (derived from Cloud Monitoring metrics, falling back to audit
// log timestamps) as the activity signal.
func AnalyzeDormancy(report ServiceAccountReport, cfg DormancyConfig) []Finding {
	links := GenerateConsoleLinks(cfg.Project, report.Email, report.LookbackWindow)

	if report.LastUsed == nil {
		// Skip NEVER_USED findings for default GCP service accounts (GAE, GCE)
		// as they may be created automatically and legitimately unused
		if isDefaultGCPServiceAccount(report.Email) {
			return nil
		}
		return []Finding{{
			ServiceAccount: report.Email,
			Severity:       SeverityCritical,
			Type:           FindingTypeNeverUsed,
			Message:        "service account has never been used (no metric data or audit log entries found)",
			Remediation:    "review whether this service account is needed; if not, disable or delete it",
			Links:          links,
		}}
	}

	daysSince := int(time.Since(*report.LastUsed).Hours() / 24)

	if daysSince >= cfg.CriticalDays {
		return []Finding{{
			ServiceAccount: report.Email,
			Severity:       SeverityCritical,
			Type:           FindingTypeDormant,
			Message:        fmt.Sprintf("service account has been inactive for %d days (threshold: %d)", daysSince, cfg.CriticalDays),
			Remediation:    "review whether this service account is still needed; consider disabling it",
			Details:        map[string]string{"days_inactive": fmt.Sprintf("%d", daysSince)},
			Links:          links,
		}}
	}

	if daysSince >= cfg.WarnDays {
		return []Finding{{
			ServiceAccount: report.Email,
			Severity:       SeverityWarn,
			Type:           FindingTypeDormant,
			Message:        fmt.Sprintf("service account has been inactive for %d days (threshold: %d)", daysSince, cfg.WarnDays),
			Remediation:    "verify this service account is still in use",
			Details:        map[string]string{"days_inactive": fmt.Sprintf("%d", daysSince)},
			Links:          links,
		}}
	}

	return nil
}
