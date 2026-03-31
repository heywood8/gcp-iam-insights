package cmd

import (
	"context"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var privilegeCmd = &cobra.Command{
	Use:   "privilege",
	Short: "Analyze service accounts for over-privilege and unused keys",
	RunE:  runPrivilege,
}

func init() {
	privilegeCmd.Flags().Bool("suggest-custom-roles", false, "Suggest custom roles with only exercised permissions instead of predefined roles")
	analyzeCmd.AddCommand(privilegeCmd)
}

func runPrivilege(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	reports, renderer, err := buildReportsAndRenderer(ctx, cmd)
	if err != nil {
		return err
	}

	registry, err := loadRoleRegistry()
	if err != nil {
		return err
	}

	suggestCustom, _ := cmd.Flags().GetBool("suggest-custom-roles")

	var findings []analyzer.Finding
	for _, r := range reports {
		findings = append(findings, analyzer.AnalyzePrivilege(r, analyzer.PrivilegeConfig{
			Registry:           registry,
			SuggestCustomRoles: suggestCustom,
			Project:            viper.GetString("project"),
		})...)
	}

	return renderer.Render(findings)
}
