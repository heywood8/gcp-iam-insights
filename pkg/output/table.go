package output

import (
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
	"github.com/olekukonko/tablewriter"
)

type tableRenderer struct {
	w io.Writer
}

// shortenSAName strips the @<project>.iam.gserviceaccount.com suffix from SA emails.
func shortenSAName(email string) string {
	if idx := strings.Index(email, "@"); idx != -1 {
		return email[:idx]
	}
	return email
}

func (r *tableRenderer) Render(findings []analyzer.Finding) error {
	table := tablewriter.NewTable(r.w,
		tablewriter.WithHeader([]string{"Service Account", "Severity", "Type", "Message", "Remediation", "Links"}),
	)

	for _, f := range findings {
		severity := colorSeverity(f.Severity)
		links := formatLinks(f.Links)
		if err := table.Append([]string{
			shortenSAName(f.ServiceAccount),
			severity,
			string(f.Type),
			f.Message,
			f.Remediation,
			links,
		}); err != nil {
			return err
		}
	}

	return table.Render()
}

func formatLinks(links map[string]string) string {
	if len(links) == 0 {
		return ""
	}
	// Return clickable links in a compact format
	result := ""
	if sa, ok := links["service_account"]; ok {
		result += "SA: " + sa + "\n"
	}
	if logs, ok := links["audit_logs"]; ok {
		result += "Logs: " + logs + "\n"
	}
	if metrics, ok := links["metrics"]; ok {
		result += "Metrics: " + metrics
	}
	return result
}

func colorSeverity(s analyzer.Severity) string {
	switch s {
	case analyzer.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint(string(s))
	case analyzer.SeverityWarn:
		return color.New(color.FgYellow).Sprint(string(s))
	default:
		return string(s)
	}
}
