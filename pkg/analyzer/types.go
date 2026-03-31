package analyzer

import "time"

// Severity represents the urgency of a finding.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarn     Severity = "WARN"
	SeverityCritical Severity = "CRITICAL"
)

// FindingType identifies the category of a finding.
type FindingType string

const (
	FindingTypePrimitiveRole FindingType = "PRIMITIVE_ROLE"
	FindingTypeOverPrivilege FindingType = "OVER_PRIVILEGE"
	FindingTypeUnusedKey     FindingType = "UNUSED_KEY"
	FindingTypeDormant       FindingType = "DORMANT"
	FindingTypeNeverUsed     FindingType = "NEVER_USED"
)

// Finding is a single actionable security observation about a service account.
type Finding struct {
	ServiceAccount string
	Severity       Severity
	Type           FindingType
	Message        string
	Remediation    string
	// Extra structured data for JSON/CSV output (key age, suggested roles, etc.)
	Details map[string]string
}

// SAKey represents a service account key with its observed authentication activity.
type SAKey struct {
	KeyID       string
	CreateTime  time.Time
	AuthnEvents int64 // from Cloud Monitoring authn_events_count
}

// ServiceAccountReport is the shared input to both analyzers. It is populated
// once per run from IAM, Asset Inventory, Cloud Monitoring, and Cloud Logging.
type ServiceAccountReport struct {
	Email       string
	UniqueID    string
	DisplayName string

	// Roles bound to this SA across the project (including inherited via Asset Inventory).
	Roles []string

	// Keys associated with this SA.
	Keys []SAKey

	// ActiveAPIs maps GCP API service names (e.g. "storage.googleapis.com") to
	// call count over the lookback window. Source: Cloud Logging audit logs.
	// Best-effort: audit logs may be incomplete if not enabled for all APIs.
	ActiveAPIs map[string]int64

	// ExercisedPerms lists IAM permissions observed in audit logs
	// (e.g. "storage.objects.get"). Best-effort: audit logs may be incomplete.
	ExercisedPerms []string

	// LastUsed is the most recent activity timestamp from audit logs.
	// Nil means no audit log entries found (may indicate never used, or logs not enabled).
	LastUsed *time.Time

	// LookbackWindow is the duration used for metric and log queries.
	LookbackWindow time.Duration
}
