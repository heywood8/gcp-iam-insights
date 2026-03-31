package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/cache"
)

// cachedLoggingClient wraps LoggingClient with disk cache.
type cachedLoggingClient struct {
	inner LoggingClient
	cache *cache.Cache
}

func NewCachedLoggingClient(inner LoggingClient, c *cache.Cache) LoggingClient {
	return &cachedLoggingClient{inner: inner, cache: c}
}

func (c *cachedLoggingClient) QueryAuditLogs(ctx context.Context, project, saEmail string, since time.Time) ([]AuditEntry, error) {
	cacheKey := fmt.Sprintf("logs-%s-%s", saEmail, since.Format("2006-01-02"))
	if data, ok, err := c.cache.Get(project, cacheKey); err == nil && ok {
		var entries []AuditEntry
		if err := json.Unmarshal(data, &entries); err == nil {
			return entries, nil
		}
	}
	entries, err := c.inner.QueryAuditLogs(ctx, project, saEmail, since)
	if err != nil {
		return nil, err
	}
	if data, err := json.Marshal(entries); err == nil {
		_ = c.cache.Set(project, cacheKey, data)
	}
	return entries, nil
}

// cachedMonitoringClient wraps MonitoringClient with disk cache.
type cachedMonitoringClient struct {
	inner MonitoringClient
	cache *cache.Cache
}

func NewCachedMonitoringClient(inner MonitoringClient, c *cache.Cache) MonitoringClient {
	return &cachedMonitoringClient{inner: inner, cache: c}
}

func (c *cachedMonitoringClient) GetAuthnEventsPerKey(ctx context.Context, project, saUniqueID string, since time.Time) (map[string]int64, error) {
	cacheKey := fmt.Sprintf("metrics-authn-%s-%s", saUniqueID, since.Format("2006-01-02"))
	if data, ok, err := c.cache.Get(project, cacheKey); err == nil && ok {
		var m map[string]int64
		if err := json.Unmarshal(data, &m); err == nil {
			return m, nil
		}
	}
	result, err := c.inner.GetAuthnEventsPerKey(ctx, project, saUniqueID, since)
	if err != nil {
		return nil, err
	}
	if data, err := json.Marshal(result); err == nil {
		_ = c.cache.Set(project, cacheKey, data)
	}
	return result, nil
}
