package roles_test

import (
	"testing"

	"github.com/heywood8/gcp-iam-insights/pkg/roles"
)

func TestFindMinimalRoles_ExactMatch(t *testing.T) {
	registry := roles.Registry{
		"roles/storage.objectViewer": {"storage.objects.get", "storage.objects.list"},
	}
	got, uncovered := registry.FindMinimalRoles([]string{"storage.objects.get", "storage.objects.list"})
	if len(got) != 1 || got[0] != "roles/storage.objectViewer" {
		t.Fatalf("expected [roles/storage.objectViewer], got %v", got)
	}
	if len(uncovered) != 0 {
		t.Fatalf("expected no uncovered perms, got %v", uncovered)
	}
}

func TestFindMinimalRoles_PrefersFewerRoles(t *testing.T) {
	registry := roles.Registry{
		"roles/storage.objectViewer":  {"storage.objects.get", "storage.objects.list"},
		"roles/storage.objectCreator": {"storage.objects.create"},
		"roles/storage.objectAdmin":   {"storage.objects.get", "storage.objects.list", "storage.objects.create", "storage.objects.delete"},
	}
	// objectAdmin covers all three needed perms with a single role
	got, uncovered := registry.FindMinimalRoles([]string{
		"storage.objects.get",
		"storage.objects.list",
		"storage.objects.create",
	})
	if len(got) != 1 || got[0] != "roles/storage.objectAdmin" {
		t.Fatalf("expected single objectAdmin role, got %v", got)
	}
	if len(uncovered) != 0 {
		t.Fatalf("expected no uncovered perms, got %v", uncovered)
	}
}

func TestFindMinimalRoles_UncoveredPermissions(t *testing.T) {
	registry := roles.Registry{
		"roles/storage.objectViewer": {"storage.objects.get"},
	}
	_, uncovered := registry.FindMinimalRoles([]string{"storage.objects.get", "bigquery.tables.list"})
	if len(uncovered) != 1 || uncovered[0] != "bigquery.tables.list" {
		t.Fatalf("expected [bigquery.tables.list] uncovered, got %v", uncovered)
	}
}

func TestLoadEmbedded(t *testing.T) {
	reg, err := roles.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(reg) == 0 {
		t.Fatal("expected non-empty registry from embedded data")
	}
	// roles/viewer is a well-known predefined role
	perms, ok := reg["roles/viewer"]
	if !ok {
		t.Fatal("expected roles/viewer in embedded registry")
	}
	if len(perms) == 0 {
		t.Fatal("expected roles/viewer to have permissions")
	}
}
