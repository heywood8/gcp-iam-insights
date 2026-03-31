package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
	"github.com/heywood8/gcp-iam-insights/pkg/output"
)

var testFindings = []analyzer.Finding{
	{
		ServiceAccount: "sa@project.iam.gserviceaccount.com",
		Severity:       analyzer.SeverityCritical,
		Type:           analyzer.FindingTypePrimitiveRole,
		Message:        "has roles/owner",
		Remediation:    "replace with narrower role",
	},
	{
		ServiceAccount: "other@project.iam.gserviceaccount.com",
		Severity:       analyzer.SeverityWarn,
		Type:           analyzer.FindingTypeDormant,
		Message:        "inactive for 45 days",
		Remediation:    "verify still needed",
	},
}

func TestTableRenderer(t *testing.T) {
	var buf bytes.Buffer
	r, err := output.NewRenderer(output.FormatTable, &buf)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	if err := r.Render(testFindings); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "sa@project.iam.gserviceaccount.com") {
		t.Error("expected SA email in table output")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("expected CRITICAL in table output")
	}
}

func TestJSONRenderer(t *testing.T) {
	var buf bytes.Buffer
	r, err := output.NewRenderer(output.FormatJSON, &buf)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	if err := r.Render(testFindings); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var got []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal JSON output: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings in JSON, got %d", len(got))
	}
}

func TestCSVRenderer(t *testing.T) {
	var buf bytes.Buffer
	r, err := output.NewRenderer(output.FormatCSV, &buf)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	if err := r.Render(testFindings); err != nil {
		t.Fatalf("Render: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// header + 2 data rows
	if len(lines) != 3 {
		t.Fatalf("expected 3 CSV lines (header + 2 rows), got %d: %q", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "service_account") {
		t.Errorf("expected CSV header, got: %s", lines[0])
	}
}

func TestNewRenderer_UnknownFormat(t *testing.T) {
	_, err := output.NewRenderer("xml", nil)
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}
