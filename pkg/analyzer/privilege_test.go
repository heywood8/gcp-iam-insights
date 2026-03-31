package analyzer_test

import (
	"testing"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
	"github.com/heywood8/gcp-iam-insights/pkg/roles"
)

func testRegistry() roles.Registry {
	return roles.Registry{
		"roles/storage.objectViewer": {"storage.objects.get", "storage.objects.list"},
		"roles/storage.objectAdmin":  {"storage.objects.get", "storage.objects.list", "storage.objects.create", "storage.objects.delete"},
		"roles/bigquery.dataViewer":  {"bigquery.tables.list", "bigquery.tables.getData"},
	}
}

func TestPrivilege_PrimitiveOwner(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email: "sa@project.iam.gserviceaccount.com",
		Roles: []string{"roles/owner"},
	}
	findings := analyzer.AnalyzePrivilege(report, analyzer.PrivilegeConfig{
		Registry: testRegistry(),
	})
	var found bool
	for _, f := range findings {
		if f.Type == analyzer.FindingTypePrimitiveRole {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected PRIMITIVE_ROLE finding for roles/owner, got %v", findings)
	}
}

func TestPrivilege_PrimitiveEditor(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email: "sa@project.iam.gserviceaccount.com",
		Roles: []string{"roles/editor"},
	}
	findings := analyzer.AnalyzePrivilege(report, analyzer.PrivilegeConfig{
		Registry: testRegistry(),
	})
	if len(findings) == 0 || findings[0].Type != analyzer.FindingTypePrimitiveRole {
		t.Fatalf("expected PRIMITIVE_ROLE finding, got %v", findings)
	}
}

func TestPrivilege_SuggestsPredefinedRoles(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email:          "sa@project.iam.gserviceaccount.com",
		Roles:          []string{"roles/storage.objectAdmin"},
		ExercisedPerms: []string{"storage.objects.get", "storage.objects.list"},
		ActiveAPIs:     map[string]int64{"storage.googleapis.com": 100},
	}
	findings := analyzer.AnalyzePrivilege(report, analyzer.PrivilegeConfig{
		Registry: testRegistry(),
	})
	var found bool
	for _, f := range findings {
		if f.Type == analyzer.FindingTypeOverPrivilege {
			found = true
			if f.Details["suggested_roles"] == "" {
				t.Fatal("expected suggested_roles in Details")
			}
		}
	}
	if !found {
		t.Fatalf("expected OVER_PRIVILEGE finding, got %v", findings)
	}
}

func TestPrivilege_NoFindingWhenRolesAlreadyMinimal(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email:          "sa@project.iam.gserviceaccount.com",
		Roles:          []string{"roles/storage.objectViewer"},
		ExercisedPerms: []string{"storage.objects.get", "storage.objects.list"},
		ActiveAPIs:     map[string]int64{"storage.googleapis.com": 50},
	}
	findings := analyzer.AnalyzePrivilege(report, analyzer.PrivilegeConfig{
		Registry: testRegistry(),
	})
	for _, f := range findings {
		if f.Type == analyzer.FindingTypeOverPrivilege {
			t.Fatalf("unexpected OVER_PRIVILEGE when roles are already minimal: %v", f)
		}
	}
}

func TestPrivilege_UnusedKey(t *testing.T) {
	createTime := time.Now().Add(-200 * 24 * time.Hour) // 200 days old
	report := analyzer.ServiceAccountReport{
		Email: "sa@project.iam.gserviceaccount.com",
		Roles: []string{"roles/storage.objectViewer"},
		Keys: []analyzer.SAKey{
			{KeyID: "key-abc123", CreateTime: createTime, AuthnEvents: 0},
		},
		ActiveAPIs: map[string]int64{"storage.googleapis.com": 50}, // SA itself is active
	}
	findings := analyzer.AnalyzePrivilege(report, analyzer.PrivilegeConfig{
		Registry: testRegistry(),
	})
	var found bool
	for _, f := range findings {
		if f.Type == analyzer.FindingTypeUnusedKey {
			found = true
			if f.Details["key_id"] == "" {
				t.Fatal("expected key_id in Details")
			}
			if f.Details["key_age_days"] == "" {
				t.Fatal("expected key_age_days in Details")
			}
		}
	}
	if !found {
		t.Fatalf("expected UNUSED_KEY finding, got %v", findings)
	}
}

func TestPrivilege_NoUnusedKeyFindingWhenSAIsAlsoDormant(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email: "sa@project.iam.gserviceaccount.com",
		Roles: []string{"roles/storage.objectViewer"},
		Keys: []analyzer.SAKey{
			{KeyID: "key-abc123", CreateTime: time.Now().Add(-100 * 24 * time.Hour), AuthnEvents: 0},
		},
		ActiveAPIs: map[string]int64{}, // SA also has no metric activity
	}
	findings := analyzer.AnalyzePrivilege(report, analyzer.PrivilegeConfig{
		Registry: testRegistry(),
	})
	for _, f := range findings {
		if f.Type == analyzer.FindingTypeUnusedKey {
			t.Fatalf("unexpected UNUSED_KEY finding when SA itself is also inactive: %v", f)
		}
	}
}

func TestPrivilege_CustomRoleSuggestion(t *testing.T) {
	report := analyzer.ServiceAccountReport{
		Email:          "sa@project.iam.gserviceaccount.com",
		Roles:          []string{"roles/storage.objectAdmin"},
		ExercisedPerms: []string{"storage.objects.get", "storage.objects.list"},
		ActiveAPIs:     map[string]int64{"storage.googleapis.com": 100},
	}
	findings := analyzer.AnalyzePrivilege(report, analyzer.PrivilegeConfig{
		Registry:           testRegistry(),
		SuggestCustomRoles: true,
		Project:            "my-test-project",
	})
	var found bool
	for _, f := range findings {
		if f.Type == analyzer.FindingTypeOverPrivilege {
			found = true
			if f.Details["gcloud_command"] == "" {
				t.Fatal("expected gcloud_command in Details when SuggestCustomRoles=true")
			}
			if f.Details["custom_role_permissions"] == "" {
				t.Fatal("expected custom_role_permissions in Details")
			}
		}
	}
	if !found {
		t.Fatalf("expected OVER_PRIVILEGE finding with custom role details, got %v", findings)
	}
}
