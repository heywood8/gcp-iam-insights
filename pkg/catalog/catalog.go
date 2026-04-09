// Package catalog fetches GCP IAM role and permission data from
// gcp-iam-catalog.unitvectorylabs.com.
package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const baseURL = "https://gcp-iam-catalog.unitvectorylabs.com"

// Client fetches role and permission data from gcp-iam-catalog.unitvectorylabs.com.
// If cacheDir is empty, responses are not cached.
type Client struct {
	http     *http.Client
	cacheDir string
	ttl      time.Duration
}

// New creates a Client with the given cache directory and TTL.
// Pass an empty cacheDir to disable caching.
func New(cacheDir string, ttl time.Duration) *Client {
	return &Client{
		http:     &http.Client{Timeout: 15 * time.Second},
		cacheDir: cacheDir,
		ttl:      ttl,
	}
}

// RolesForPermission returns the names of all predefined roles that include perm.
// Fetches /permissions/{perm}.html and parses the role table.
func (c *Client) RolesForPermission(ctx context.Context, perm string) ([]string, error) {
	url := fmt.Sprintf("%s/permissions/%s.html", baseURL, perm)
	body, err := c.fetch(ctx, "perm-"+perm, url)
	if err != nil {
		return nil, err
	}
	return parseRoleTable(body)
}

// PermissionsForRole returns the full set of permissions included in role.
// role must be in the form "roles/service.name".
// Fetches /roles/{service.name}.html and parses the permission links.
func (c *Client) PermissionsForRole(ctx context.Context, role string) ([]string, error) {
	rolePath := strings.TrimPrefix(role, "roles/")
	url := fmt.Sprintf("%s/roles/%s.html", baseURL, rolePath)
	body, err := c.fetch(ctx, "role-"+role, url)
	if err != nil {
		return nil, err
	}
	return parsePermissionLinks(body)
}

func (c *Client) fetch(ctx context.Context, cacheKey, url string) ([]byte, error) {
	if c.cacheDir != "" {
		if data, ok := c.cacheGet(cacheKey); ok {
			return data, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if c.cacheDir != "" {
		_ = c.cacheSet(cacheKey, data)
	}
	return data, nil
}

func (c *Client) cachePath(key string) string {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	return filepath.Join(c.cacheDir, hash)
}

func (c *Client) cacheGet(key string) ([]byte, bool) {
	p := c.cachePath(key)
	info, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > c.ttl {
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return data, true
}

func (c *Client) cacheSet(key string, data []byte) error {
	p := c.cachePath(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

// parseRoleTable extracts role names from <tr class="role-row"> elements on permission pages.
func parseRoleTable(body []byte) ([]string, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("parse HTML: %w", err)
	}
	var roles []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "tr" && hasClass(n, "role-row") {
			if role := firstAnchorText(n, "roles/"); role != "" {
				roles = append(roles, role)
			}
			return // don't recurse further into the row
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return roles, nil
}

// parsePermissionLinks extracts permission names from <a href="../permissions/*.html"> on role pages.
func parsePermissionLinks(body []byte) ([]string, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("parse HTML: %w", err)
	}
	seen := make(map[string]bool)
	var perms []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" &&
					strings.HasPrefix(a.Val, "../permissions/") &&
					strings.HasSuffix(a.Val, ".html") {
					perm := strings.TrimSuffix(strings.TrimPrefix(a.Val, "../permissions/"), ".html")
					if perm != "" && !seen[perm] {
						seen[perm] = true
						perms = append(perms, perm)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return perms, nil
}

func hasClass(n *html.Node, class string) bool {
	for _, a := range n.Attr {
		if a.Key == "class" {
			for _, c := range strings.Fields(a.Val) {
				if c == class {
					return true
				}
			}
		}
	}
	return false
}

func firstAnchorText(n *html.Node, prefix string) string {
	if n.Type == html.ElementNode && n.Data == "a" {
		if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
			if text := strings.TrimSpace(n.FirstChild.Data); strings.HasPrefix(text, prefix) {
				return text
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if text := firstAnchorText(c, prefix); text != "" {
			return text
		}
	}
	return ""
}
