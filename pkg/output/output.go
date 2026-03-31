package output

import (
	"fmt"
	"io"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
)

// Format represents a supported output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
)

// Renderer writes findings to an io.Writer in a specific format.
type Renderer interface {
	Render(findings []analyzer.Finding) error
}

// NewRenderer returns a Renderer for the given format.
func NewRenderer(format Format, w io.Writer) (Renderer, error) {
	switch format {
	case FormatTable:
		return &tableRenderer{w: w}, nil
	case FormatJSON:
		return &jsonRenderer{w: w}, nil
	case FormatCSV:
		return &csvRenderer{w: w}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q: must be table, json, or csv", format)
	}
}
