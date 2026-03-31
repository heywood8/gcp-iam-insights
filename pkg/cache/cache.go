package cache

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cache stores byte payloads keyed by (project, serviceAccountEmail) with a TTL.
// Files are stored at <baseDir>/<project>/<sha256(email)>.json
type Cache struct {
	baseDir string
	ttl     time.Duration
}

func New(baseDir string, ttl time.Duration) *Cache {
	return &Cache{baseDir: baseDir, ttl: ttl}
}

// DefaultBaseDir returns ~/.cache/gcp-iam-insights
func DefaultBaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".cache", "gcp-iam-insights"), nil
}

func (c *Cache) path(project, email string) string {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(email)))
	return filepath.Join(c.baseDir, project, hash+".json")
}

// Set writes data to the cache for the given project and service account email.
func (c *Cache) Set(project, email string, data []byte) error {
	p := c.path(project, email)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	return os.WriteFile(p, data, 0o644)
}

// Get retrieves cached data for the given project and service account email.
// Returns (data, true, nil) on a valid hit, (nil, false, nil) on a miss or expired entry.
func (c *Cache) Get(project, email string) ([]byte, bool, error) {
	p := c.path(project, email)
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("stat cache file: %w", err)
	}
	if time.Since(info.ModTime()) > c.ttl {
		return nil, false, nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false, fmt.Errorf("read cache file: %w", err)
	}
	return data, true, nil
}
