package cmd

import (
	"context"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
	"github.com/spf13/cobra"
)

var dormancyCmd = &cobra.Command{
	Use:   "dormancy",
	Short: "Analyze service accounts for inactivity and never-used accounts",
	RunE:  runDormancy,
}

func init() {
	dormancyCmd.Flags().Int("warn-days", 30, "Days of inactivity before WARN finding")
	dormancyCmd.Flags().Int("critical-days", 90, "Days of inactivity before CRITICAL finding")
	analyzeCmd.AddCommand(dormancyCmd)
}

func runDormancy(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	reports, renderer, err := buildReportsAndRenderer(ctx, cmd)
	if err != nil {
		return err
	}

	warnDays, _ := cmd.Flags().GetInt("warn-days")
	criticalDays, _ := cmd.Flags().GetInt("critical-days")

	var findings []analyzer.Finding
	for _, r := range reports {
		findings = append(findings, analyzer.AnalyzeDormancy(r, analyzer.DormancyConfig{
			WarnDays:     warnDays,
			CriticalDays: criticalDays,
		})...)
	}

	return renderer.Render(findings)
}
