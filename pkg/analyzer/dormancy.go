package analyzer

import (
	"fmt"
	"time"
)

// DormancyConfig holds threshold configuration for the dormancy analyzer.
type DormancyConfig struct {
	WarnDays     int
	CriticalDays int
}

// AnalyzeDormancy returns dormancy findings for a single ServiceAccountReport.
// It uses LastUsed (derived from Cloud Monitoring metrics, falling back to audit
// log timestamps) as the activity signal.
func AnalyzeDormancy(report ServiceAccountReport, cfg DormancyConfig) []Finding {
	if report.LastUsed == nil {
		return []Finding{{
			ServiceAccount: report.Email,
			Severity:       SeverityCritical,
			Type:           FindingTypeNeverUsed,
			Message:        "service account has never been used (no metric data or audit log entries found)",
			Remediation:    "review whether this service account is needed; if not, disable or delete it",
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
		}}
	}

	return nil
}
