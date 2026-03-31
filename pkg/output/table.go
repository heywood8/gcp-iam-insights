package output

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
	"github.com/olekukonko/tablewriter"
)

type tableRenderer struct {
	w io.Writer
}

func (r *tableRenderer) Render(findings []analyzer.Finding) error {
	table := tablewriter.NewTable(r.w,
		tablewriter.WithHeader([]string{"Service Account", "Severity", "Type", "Message", "Remediation"}),
	)

	for _, f := range findings {
		severity := colorSeverity(f.Severity)
		if err := table.Append([]string{
			shortenSAName(f.ServiceAccount),
			severity,
			string(f.Type),
			f.Message,
			f.Remediation,
		}); err != nil {
			return err
		}
	}

	if err := table.Render(); err != nil {
		return err
	}

	// Print link templates footer
	fmt.Fprintf(r.w, "\n%s\n", color.New(color.Bold).Sprint("GCP Console Links:"))
	fmt.Fprintf(r.w, "  Service Account: https://console.cloud.google.com/iam-admin/serviceaccounts/details/<SA_EMAIL>?project=<PROJECT>\n")
	fmt.Fprintf(r.w, "  Audit Logs:      https://console.cloud.google.com/logs/query;query=protoPayload.authenticationInfo.principalEmail=\"<SA_EMAIL>\"?project=<PROJECT>\n")
	fmt.Fprintf(r.w, "  Metrics:         https://console.cloud.google.com/iam-admin/serviceaccounts/details/<SA_EMAIL>/metrics?project=<PROJECT>\n")

	return nil
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
