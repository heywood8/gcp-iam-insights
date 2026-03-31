package cache_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/cache"
)

func TestSetAndGet(t *testing.T) {
	dir := t.TempDir()
	c := cache.New(dir, time.Hour)

	err := c.Set("my-project", "sa@example.iam.gserviceaccount.com", []byte(`{"foo":"bar"}`))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	data, ok, err := c.Get("my-project", "sa@example.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if string(data) != `{"foo":"bar"}` {
		t.Fatalf("unexpected data: %s", data)
	}
}

func TestGetMissWhenExpired(t *testing.T) {
	dir := t.TempDir()
	c := cache.New(dir, -time.Second) // TTL already expired

	err := c.Set("my-project", "sa@example.iam.gserviceaccount.com", []byte(`{}`))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	_, ok, err := c.Get("my-project", "sa@example.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected cache miss for expired entry, got hit")
	}
}

func TestGetMissWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	c := cache.New(dir, time.Hour)

	_, ok, err := c.Get("my-project", "nobody@example.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatal("expected miss for nonexistent entry, got hit")
	}
}

func TestCacheFileIsUnderProjectDir(t *testing.T) {
	dir := t.TempDir()
	c := cache.New(dir, time.Hour)

	_ = c.Set("proj-123", "sa@example.iam.gserviceaccount.com", []byte(`{}`))

	entries, _ := os.ReadDir(filepath.Join(dir, "proj-123"))
	if len(entries) != 1 {
		t.Fatalf("expected 1 cache file under proj-123/, got %d", len(entries))
	}
}
