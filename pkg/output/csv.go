package output

import (
	"encoding/csv"
	"fmt"
	"io"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
)

type csvRenderer struct {
	w io.Writer
}

func (r *csvRenderer) Render(findings []analyzer.Finding) error {
	w := csv.NewWriter(r.w)
	if err := w.Write([]string{"service_account", "severity", "type", "message", "remediation", "service_account_url", "audit_logs_url", "metrics_url"}); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}
	for _, f := range findings {
		if err := w.Write([]string{
			f.ServiceAccount,
			string(f.Severity),
			string(f.Type),
			f.Message,
			f.Remediation,
			f.Links["service_account"],
			f.Links["audit_logs"],
			f.Links["metrics"],
		}); err != nil {
			return fmt.Errorf("write CSV row: %w", err)
		}
	}
	w.Flush()
	return w.Error()
}
