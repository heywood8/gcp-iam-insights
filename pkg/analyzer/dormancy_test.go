package analyzer_test

import (
	"testing"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
)

func ptr(t time.Time) *time.Time { return &t }

func TestDormancy_Active(t *testing.T) {
	now := time.Now()
	report := analyzer.ServiceAccountReport{
		Email:    "active@project.iam.gserviceaccount.com",
		LastUsed: ptr(now.Add(-10 * 24 * time.Hour)), // 10 days ago
	}
	findings := analyzer.AnalyzeDormancy(report, analyzer.DormancyConfig{
		WarnDays:     30,
		CriticalDays: 90,
	})
	if len(findings) != 0 {
		t.Fatalf("expected no findings for active SA, got %v", findings)
	}
}

func TestDormancy_Warn(t *testing.T) {
	now := time.Now()
	report := analyzer.ServiceAccountReport{
		Email:    "stale@project.iam.gserviceaccount.com",
		LastUsed: ptr(now.Add(-45 * 24 * time.Hour)), // 45 days ago
	}
	findings := analyzer.AnalyzeDormancy(report, analyzer.DormancyConfig{
		WarnDays:     30,
		CriticalDays: 90,
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 WARN finding, got %d", len(findings))
	}
	if findings[0].Severity != analyzer.SeverityWarn {
		t.Fatalf("expected WARN, got %s", findings[0].Severity)
	}
	if findings[0].Type != analyzer.FindingTypeDormant {
		t.Fatalf("expected DORMANT, got %s", findings[0].Type)
	}
}

func TestDormancy_Critical(t *testing.T) {
	now := time.Now()
	report := analyzer.ServiceAccountReport{
		Email:    "old@project.iam.gserviceaccount.com",
		LastUsed: ptr(now.Add(-120 * 24 * time.Hour)), // 120 days ago
	}
	findings := analyzer.AnalyzeDormancy(report, analyzer.DormancyConfig{
		WarnDays:     30,
		CriticalDays: 90,
	})
	if len(findings) != 1 || findings[0].Severity != analyzer.SeverityCritical {
		t.Fatalf("expected CRITICAL finding, got %v", findings)
	}
}

func TestDormancy_NeverUsed(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email:    "ghost@project.iam.gserviceaccount.com",
		LastUsed: nil,
	}
	findings := analyzer.AnalyzeDormancy(report, analyzer.DormancyConfig{
		WarnDays:     30,
		CriticalDays: 90,
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != analyzer.FindingTypeNeverUsed {
		t.Fatalf("expected NEVER_USED, got %s", findings[0].Type)
	}
	if findings[0].Severity != analyzer.SeverityCritical {
		t.Fatalf("expected CRITICAL for never-used, got %s", findings[0].Severity)
	}
}

func TestDormancy_DefaultGAE_NeverUsed(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email:    "my-project@appspot.gserviceaccount.com",
		LastUsed: nil,
	}
	findings := analyzer.AnalyzeDormancy(report, analyzer.DormancyConfig{
		Project:      "my-project",
		WarnDays:     30,
		CriticalDays: 90,
	})
	if len(findings) != 0 {
		t.Fatalf("expected no findings for default GAE SA, got %v", findings)
	}
}

func TestDormancy_DefaultGCE_NeverUsed(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email:    "123456789-compute@developer.gserviceaccount.com",
		LastUsed: nil,
	}
	findings := analyzer.AnalyzeDormancy(report, analyzer.DormancyConfig{
		Project:      "my-project",
		WarnDays:     30,
		CriticalDays: 90,
	})
	if len(findings) != 0 {
		t.Fatalf("expected no findings for default GCE SA, got %v", findings)
	}
}
