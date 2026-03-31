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
	GetRequestCountPerAPI(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error)
	GetAuthnEventsPerKey(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error)
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

func (c *realMonitoringClient) GetRequestCountPerAPI(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error) {
	return c.queryTimeSeries(ctx, project, saUniqueID,
		"iam.googleapis.com/service_account/request_count",
		"service",
		since,
	)
}

func (c *realMonitoringClient) GetAuthnEventsPerKey(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error) {
	return c.queryTimeSeries(ctx, project, saUniqueID,
		"iam.googleapis.com/service_account/authn_events_count",
		"key_id",
		since,
	)
}

func (c *realMonitoringClient) queryTimeSeries(
	ctx context.Context,
	project, saUniqueID, metricType, labelKey string,
	since time.Time,
) (map[string]int64, error) {
	filter := fmt.Sprintf(
		`metric.type="%s" AND resource.type="iam_service_account" AND resource.labels.unique_id="%s"`,
		metricType, saUniqueID,
	)
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
			return nil, fmt.Errorf("iterate time series for %s: %w", metricType, err)
		}

		labelVal := ts.Metric.Labels[labelKey]
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
