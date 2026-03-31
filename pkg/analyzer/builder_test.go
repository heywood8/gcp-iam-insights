package analyzer_test

import (
	"context"
	"testing"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
	"github.com/heywood8/gcp-iam-insights/pkg/gcp"
)

// fakeIAM implements gcp.IAMClient.
type fakeIAM struct{}

func (f *fakeIAM) ListServiceAccounts(_ context.Context, _ string) ([]gcp.ServiceAccount, error) {
	return []gcp.ServiceAccount{
		{Email: "sa@project.iam.gserviceaccount.com", UniqueID: "uid-123", DisplayName: "Test SA"},
	}, nil
}

func (f *fakeIAM) ListProjectBindings(_ context.Context, _ string) ([]gcp.ProjectBinding, error) {
	return []gcp.ProjectBinding{
		{Role: "roles/storage.objectAdmin", Members: []string{"serviceAccount:sa@project.iam.gserviceaccount.com"}},
	}, nil
}

func (f *fakeIAM) ListServiceAccountKeys(_ context.Context, _, _ string) ([]gcp.SAKey, error) {
	return []gcp.SAKey{
		{KeyID: "key-abc", CreateTime: time.Now().Add(-30 * 24 * time.Hour)},
	}, nil
}

// fakeAsset implements gcp.AssetClient.
type fakeAsset struct{}

func (f *fakeAsset) SearchIAMPolicies(_ context.Context, _ string) ([]gcp.ProjectBinding, error) {
	return nil, nil // no inherited bindings in this test
}

// fakeLogging implements gcp.LoggingClient.
type fakeLogging struct{}

func (f *fakeLogging) QueryAuditLogs(_ context.Context, _, _ string, _ time.Time) ([]gcp.AuditEntry, error) {
	ts := time.Now().Add(-5 * 24 * time.Hour)
	return []gcp.AuditEntry{
		{Timestamp: ts, MethodName: "storage.objects.get", ServiceName: "storage.googleapis.com"},
	}, nil
}

// fakeMonitoring implements gcp.MonitoringClient.
type fakeMonitoring struct{}

func (f *fakeMonitoring) GetAuthnEventsPerKey(_ context.Context, _, _ string, _ time.Time) (map[string]int64, error) {
	return map[string]int64{"key-abc": 10}, nil
}

func TestBuildReports_SingleSA(t *testing.T) {
	ctx := context.Background()
	reports, err := analyzer.BuildReports(ctx, analyzer.BuildConfig{
		Project:        "my-project",
		LookbackWindow: 90 * 24 * time.Hour,
		IAM:            &fakeIAM{},
		Asset:          &fakeAsset{},
		Logging:        &fakeLogging{},
		Monitoring:     &fakeMonitoring{},
	})
	if err != nil {
		t.Fatalf("BuildReports: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}
	r := reports[0]
	if r.Email != "sa@project.iam.gserviceaccount.com" {
		t.Errorf("unexpected email: %s", r.Email)
	}
	if len(r.Roles) != 1 || r.Roles[0] != "roles/storage.objectAdmin" {
		t.Errorf("unexpected roles: %v", r.Roles)
	}
	if r.ActiveAPIs["storage.googleapis.com"] != 1 {
		t.Errorf("unexpected ActiveAPIs (should be call count from audit logs): %v", r.ActiveAPIs)
	}
	if len(r.ExercisedPerms) == 0 {
		t.Error("expected exercised perms from audit logs")
	}
	if r.LastUsed == nil {
		t.Error("expected LastUsed to be set")
	}
	if len(r.Keys) != 1 || r.Keys[0].AuthnEvents != 10 {
		t.Errorf("unexpected keys: %v", r.Keys)
	}
}

func TestBuildReports_SingleSAFilter(t *testing.T) {
	ctx := context.Background()
	reports, err := analyzer.BuildReports(ctx, analyzer.BuildConfig{
		Project:              "my-project",
		LookbackWindow:       90 * 24 * time.Hour,
		ServiceAccountFilter: "other@project.iam.gserviceaccount.com",
		IAM:                  &fakeIAM{},
		Asset:                &fakeAsset{},
		Logging:              &fakeLogging{},
		Monitoring:           &fakeMonitoring{},
	})
	if err != nil {
		t.Fatalf("BuildReports: %v", err)
	}
	// fakeIAM returns one SA that doesn't match the filter
	if len(reports) != 0 {
		t.Fatalf("expected 0 reports after filter, got %d", len(reports))
	}
}
