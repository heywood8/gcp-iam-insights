package gcp

import (
	"context"
	"fmt"
	"time"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	monitoringpb "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MonitoringClient is the interface for Cloud Monitoring metric queries.
type MonitoringClient interface {
	GetAuthnEventsPerKey(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error)
	GetAPIUsagePerService(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error)
}

type realMonitoringClient struct {
	client *monitoring.MetricClient
}

// NewMonitoringClient creates a real MonitoringClient.
func NewMonitoringClient(ctx context.Context, opts ...option.ClientOption) (MonitoringClient, error) {
	c, err := monitoring.NewMetricClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create monitoring client: %w", err)
	}
	return &realMonitoringClient{client: c}, nil
}

func (c *realMonitoringClient) GetAuthnEventsPerKey(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error) {
	// Key-level metric uses metric.labels.key_id, not resource.labels
	// Filter by service account unique_id at resource level to get all keys for this SA
	filter := fmt.Sprintf(
		`metric.type="iam.googleapis.com/service_account/key/authn_events_count" AND resource.type="iam_service_account" AND resource.labels.unique_id="%s"`,
		saUniqueID,
	)
	return c.queryTimeSeriesWithMetricLabel(ctx, project, filter, "key_id", since)
}

func (c *realMonitoringClient) GetAPIUsagePerService(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error) {
	// Service account level metric uses resource.labels.unique_id
	filter := fmt.Sprintf(
		`metric.type="iam.googleapis.com/service_account/authn_events_count" AND resource.type="iam_service_account" AND resource.labels.unique_id="%s"`,
		saUniqueID,
	)
	return c.queryTimeSeriesWithMetricLabel(ctx, project, filter, "service", since)
}

func (c *realMonitoringClient) queryTimeSeriesWithMetricLabel(
	ctx context.Context,
	project, filter, metricLabelKey string,
	since time.Time,
) (map[string]int64, error) {
	req := &monitoringpb.ListTimeSeriesRequest{
		Name:   "projects/" + project,
		Filter: filter,
		Interval: &monitoringpb.TimeInterval{
			StartTime: timestamppb.New(since),
			EndTime:   timestamppb.Now(),
		},
		View: monitoringpb.ListTimeSeriesRequest_FULL,
	}

	result := map[string]int64{}
	it := c.client.ListTimeSeries(ctx, req)
	for {
		ts, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iterate time series: %w", err)
		}

		// Extract label value from metric labels
		labelVal := ts.Metric.Labels[metricLabelKey]
		if labelVal == "" {
			labelVal = "unknown"
		}

		var sum int64
		for _, pt := range ts.Points {
			sum += pt.Value.GetInt64Value()
		}
		result[labelVal] += sum
	}
	return result, nil
}
