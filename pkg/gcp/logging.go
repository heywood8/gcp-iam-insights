package gcp

import (
	"context"
	"fmt"
	"time"

	logging "cloud.google.com/go/logging/apiv2"
	loggingpb "cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
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

type realLoggingClient struct {
	client *logging.Client
}

// NewLoggingClient creates a real LoggingClient.
func NewLoggingClient(ctx context.Context, opts ...option.ClientOption) (LoggingClient, error) {
	c, err := logging.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create logging client: %w", err)
	}
	return &realLoggingClient{client: c}, nil
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

	req := &loggingpb.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + project},
		Filter:        filter,
		OrderBy:       "timestamp desc",
	}

	it := c.client.ListLogEntries(ctx, req)
	result := make(map[string][]AuditEntry)

	// Initialize empty slices for all requested SAs
	for _, email := range saEmails {
		result[email] = []AuditEntry{}
	}

	for {
		entry, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iterate log entries: %w", err)
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

		// Group by service account
		if ae.ServiceAccount != "" {
			result[ae.ServiceAccount] = append(result[ae.ServiceAccount], ae)
		}
	}
	return result, nil
}
