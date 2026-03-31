package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
)

type jsonRenderer struct {
	w io.Writer
}

func (r *jsonRenderer) Render(findings []analyzer.Finding) error {
	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}
