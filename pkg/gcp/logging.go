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
	Timestamp   time.Time
	MethodName  string // e.g. "storage.objects.get"
	ServiceName string // e.g. "storage.googleapis.com"
}

// LoggingClient is the interface for Cloud Logging audit log queries.
type LoggingClient interface {
	QueryAuditLogs(ctx context.Context, project, saEmail string, since time.Time) ([]AuditEntry, error)
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
	filter := fmt.Sprintf(
		`protoPayload.authenticationInfo.principalEmail="%s" `+
			`AND (logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" `+
			`OR logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access") `+
			`AND timestamp>="%s"`,
		saEmail, project, project, since.UTC().Format(time.RFC3339),
	)

	req := &loggingpb.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + project},
		Filter:        filter,
		OrderBy:       "timestamp desc",
	}

	it := c.client.ListLogEntries(ctx, req)
	var entries []AuditEntry
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

		// Extract methodName and serviceName from protoPayload.
		// GCP audit logs use protoPayload containing google.cloud.audit.AuditLog.
		// The SDK represents this as a Struct after unpacking.
		var payload *structpb.Struct
		if pp := entry.GetProtoPayload(); pp != nil {
			payload = &structpb.Struct{}
			if err := pp.UnmarshalTo(payload); err == nil {
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

		entries = append(entries, ae)
	}
	return entries, nil
}
