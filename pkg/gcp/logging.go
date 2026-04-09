package gcp

import (
	"context"
	"fmt"
	"os"
	"time"

	logging "cloud.google.com/go/logging/apiv2"
	loggingpb "cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// AuditEntry represents a single relevant audit log entry for a SA.
type AuditEntry struct {
	ServiceAccount string // principalEmail from the audit log
	Timestamp      time.Time
	MethodName     string // e.g. "storage.objects.get"
	ServiceName    string // e.g. "storage.googleapis.com"
}

// LoggingClient is the interface for Cloud Logging audit log queries.
type LoggingClient interface {
	QueryAuditLogs(ctx context.Context, project, saEmail string, since time.Time) ([]AuditEntry, error)
	QueryAuditLogsBatch(ctx context.Context, project string, saEmails []string, since time.Time) (map[string][]AuditEntry, error)
}

// DefaultMaxLogEntriesPerSA is the maximum audit log entries read per service
// account in a single batch query. Limits Cloud Logging read API calls.
const DefaultMaxLogEntriesPerSA = 1000

type realLoggingClient struct {
	client          *logging.Client
	maxEntriesPerSA int32
}

// NewLoggingClient creates a real LoggingClient.
// maxEntriesPerSA caps how many log entries are read per service account;
// pass 0 to use DefaultMaxLogEntriesPerSA.
func NewLoggingClient(ctx context.Context, maxEntriesPerSA int32, opts ...option.ClientOption) (LoggingClient, error) {
	c, err := logging.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create logging client: %w", err)
	}
	if maxEntriesPerSA <= 0 {
		maxEntriesPerSA = DefaultMaxLogEntriesPerSA
	}
	return &realLoggingClient{client: c, maxEntriesPerSA: maxEntriesPerSA}, nil
}

func (c *realLoggingClient) QueryAuditLogs(ctx context.Context, project, saEmail string, since time.Time) ([]AuditEntry, error) {
	result, err := c.QueryAuditLogsBatch(ctx, project, []string{saEmail}, since)
	if err != nil {
		return nil, err
	}
	return result[saEmail], nil
}

func (c *realLoggingClient) QueryAuditLogsBatch(ctx context.Context, project string, saEmails []string, since time.Time) (map[string][]AuditEntry, error) {
	// Build filter for multiple service accounts using OR
	// Format: (principalEmail="sa1" OR principalEmail="sa2" OR ...) AND logName... AND timestamp...
	emailFilters := ""
	for i, email := range saEmails {
		if i > 0 {
			emailFilters += " OR "
		}
		emailFilters += fmt.Sprintf(`protoPayload.authenticationInfo.principalEmail="%s"`, email)
	}

	filter := fmt.Sprintf(
		`(%s) `+
			`AND (logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" `+
			`OR logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access") `+
			`AND timestamp>="%s"`,
		emailFilters, project, project, since.UTC().Format(time.RFC3339),
	)
	fmt.Fprintf(os.Stderr, "Cloud Logging filter query: %s\n", filter)

	req := &loggingpb.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + project},
		Filter:        filter,
		OrderBy:       "timestamp desc",
		PageSize:      c.maxEntriesPerSA,
	}

	// Retry on quota exhaustion: the iterator is not resumable, so we restart from scratch.
	// The Cloud Logging read quota resets every 60s, so we must wait >60s between attempts
	// to land in a fresh quota window. A fixed 65s wait is safe and predictable.
	const (
		maxRetries   = 3
		quotaBackoff = 65 * time.Second
	)
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			fmt.Fprintf(os.Stderr, "warning: logging quota exceeded, retrying in %v (attempt %d/%d)...\n", quotaBackoff, attempt+1, maxRetries)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(quotaBackoff):
			}
		}
		result, err := c.iterateLogEntries(ctx, req, saEmails)
		if err == nil {
			return result, nil
		}
		if !isQuotaError(err) {
			return nil, fmt.Errorf("iterate log entries: %w", err)
		}
		lastErr = err
	}
	return nil, fmt.Errorf("iterate log entries: quota exceeded after %d attempts: %w", maxRetries, lastErr)
}

func (c *realLoggingClient) iterateLogEntries(ctx context.Context, req *loggingpb.ListLogEntriesRequest, saEmails []string) (map[string][]AuditEntry, error) {
	it := c.client.ListLogEntries(ctx, req)
	result := make(map[string][]AuditEntry, len(saEmails))

	// Track per-SA entry counts so we stop once every SA has hit maxEntriesPerSA.
	// Entries arrive in timestamp desc order, so the first N per SA are always the most recent.
	countBySA := make(map[string]int, len(saEmails))
	saSet := make(map[string]bool, len(saEmails))
	for _, email := range saEmails {
		result[email] = []AuditEntry{}
		saSet[email] = true
	}
	maxPerSA := int(c.maxEntriesPerSA)
	saturated := 0

	for {
		// All SAs have hit their cap — no need to keep paging.
		if saturated >= len(saEmails) {
			break
		}

		entry, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		ae := AuditEntry{
			Timestamp: entry.Timestamp.AsTime(),
		}

		// Extract principalEmail, methodName and serviceName from protoPayload.
		// GCP audit logs use protoPayload containing google.cloud.audit.AuditLog.
		// The SDK represents this as a Struct after unpacking.
		var payload *structpb.Struct
		if pp := entry.GetProtoPayload(); pp != nil {
			payload = &structpb.Struct{}
			if err := pp.UnmarshalTo(payload); err == nil {
				// Extract principalEmail from authenticationInfo
				if authInfo, ok := payload.Fields["authenticationInfo"]; ok {
					if authStruct := authInfo.GetStructValue(); authStruct != nil {
						if pe, ok := authStruct.Fields["principalEmail"]; ok {
							ae.ServiceAccount = pe.GetStringValue()
						}
					}
				}
				if mn, ok := payload.Fields["methodName"]; ok {
					ae.MethodName = mn.GetStringValue()
				}
				if sn, ok := payload.Fields["serviceName"]; ok {
					ae.ServiceName = sn.GetStringValue()
				}
			}
		}

		// Fallback: try jsonPayload for non-audit structured logs
		if ae.MethodName == "" && ae.ServiceName == "" {
			if jp := entry.GetJsonPayload(); jp != nil {
				if mn, ok := jp.Fields["methodName"]; ok {
					ae.MethodName = mn.GetStringValue()
				}
				if sn, ok := jp.Fields["serviceName"]; ok {
					ae.ServiceName = sn.GetStringValue()
				}
			}
		}

		// Group by service account, respecting the per-SA cap.
		if ae.ServiceAccount != "" && saSet[ae.ServiceAccount] {
			if countBySA[ae.ServiceAccount] < maxPerSA {
				result[ae.ServiceAccount] = append(result[ae.ServiceAccount], ae)
				countBySA[ae.ServiceAccount]++
				if countBySA[ae.ServiceAccount] == maxPerSA {
					saturated++
				}
			}
		}
	}
	return result, nil
}

func isQuotaError(err error) bool {
	if s, ok := status.FromError(err); ok {
		return s.Code() == codes.ResourceExhausted
	}
	return false
}
