package output

import (
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
			f.ServiceAccount,
			severity,
			string(f.Type),
			f.Message,
			f.Remediation,
		}); err != nil {
			return err
		}
	}

	return table.Render()
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
