package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/analyzer"
	"github.com/heywood8/gcp-iam-insights/pkg/auth"
	"github.com/heywood8/gcp-iam-insights/pkg/cache"
	"github.com/heywood8/gcp-iam-insights/pkg/catalog"
	"github.com/heywood8/gcp-iam-insights/pkg/gcp"
	"github.com/heywood8/gcp-iam-insights/pkg/output"
	"github.com/heywood8/gcp-iam-insights/pkg/roles"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze service accounts (runs both privilege and dormancy checks)",
	RunE:  runAnalyze,
}

func init() {
	analyzeCmd.PersistentFlags().String("service-account", "", "Analyze only this service account email")
	analyzeCmd.Flags().Bool("suggest-custom-roles", false, "Suggest custom roles with only exercised permissions instead of predefined roles")
	analyzeCmd.Flags().Int("warn-days", 30, "Days of inactivity before WARN finding")
	analyzeCmd.Flags().Int("critical-days", 90, "Days of inactivity before CRITICAL finding")
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	reports, renderer, err := buildReportsAndRenderer(ctx, cmd)
	if err != nil {
		return err
	}

	if len(reports) == 0 {
		fmt.Fprintln(os.Stderr, "No service accounts to analyze")
		return nil
	}

	roleRegistry, err := loadRoleRegistry()
	if err != nil {
		return err
	}

	catalogClient := buildCatalogClient()
	suggestCustom, _ := cmd.Flags().GetBool("suggest-custom-roles")
	warnDays, _ := cmd.Flags().GetInt("warn-days")
	criticalDays, _ := cmd.Flags().GetInt("critical-days")

	fmt.Fprintf(os.Stderr, "Running privilege and dormancy analyzers...\n")
	var all []analyzer.Finding
	for _, r := range reports {
		privCfg := analyzer.PrivilegeConfig{
			Registry:           roleRegistry,
			SuggestCustomRoles: suggestCustom,
			Project:            viper.GetString("project"),
			Catalog:            catalogClient,
		}
		all = append(all, analyzer.AnalyzePrivilege(r, privCfg)...)
		catalogFindings, err := analyzer.AnalyzeCatalogPrivilege(ctx, r, privCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: catalog privilege analysis for %s: %v\n", r.Email, err)
		}
		all = append(all, catalogFindings...)
		all = append(all, analyzer.AnalyzeDormancy(r, analyzer.DormancyConfig{
			Project:      viper.GetString("project"),
			WarnDays:     warnDays,
			CriticalDays: criticalDays,
		})...)
	}

	fmt.Fprintf(os.Stderr, "Found %d finding(s)\n\n", len(all))
	return renderer.Render(all)
}

// buildReportsAndRenderer is the shared setup used by all analyze subcommands.
func buildReportsAndRenderer(ctx context.Context, cmd *cobra.Command) ([]analyzer.ServiceAccountReport, output.Renderer, error) {
	project := viper.GetString("project")
	if project == "" {
		return nil, nil, fmt.Errorf("--project is required")
	}

	credsCfg := auth.Config{
		ImpersonateServiceAccount: viper.GetString("impersonate_service_account"),
		CredentialsFile:           viper.GetString("credentials"),
	}

	scopes := []string{
		"https://www.googleapis.com/auth/cloud-platform.read-only",
	}
	opts, err := auth.Resolve(ctx, credsCfg, scopes...)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve credentials: %w", err)
	}

	iamClient, err := gcp.NewIAMClient(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("create IAM client: %w", err)
	}
	assetClient, err := gcp.NewAssetClient(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("create asset client: %w", err)
	}
	maxLogEntries := int32(viper.GetInt("max_log_entries"))
	loggingClient, err := gcp.NewLoggingClient(ctx, maxLogEntries, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("create logging client: %w", err)
	}
	monitoringClient, err := gcp.NewMonitoringClient(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("create monitoring client: %w", err)
	}

	lookbackDays := viper.GetInt("lookback_days")
	if lookbackDays == 0 {
		lookbackDays = 90
	}
	// Auto-extend lookback only when critical-days is explicitly set by the user.
	if criticalDays, ok := resolveExplicitCriticalDays(cmd); ok && criticalDays > lookbackDays {
		lookbackDays = criticalDays
	}
	lookback := time.Duration(lookbackDays) * 24 * time.Hour

	saFilter := resolveServiceAccountFilter(cmd)

	// Wrap logging + monitoring clients with cache if not disabled.
	noCache := viper.GetBool("no_cache")
	cacheTTL := viper.GetDuration("cache_ttl")
	var loggingCached gcp.LoggingClient = loggingClient
	var monitoringCached gcp.MonitoringClient = monitoringClient
	if !noCache {
		baseDir, err := cache.DefaultBaseDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not determine cache dir, skipping cache:", err)
		} else {
			c := cache.New(baseDir, cacheTTL)
			loggingCached = gcp.NewCachedLoggingClient(loggingClient, c)
			monitoringCached = gcp.NewCachedMonitoringClient(monitoringClient, c)
		}
	}

	reports, err := analyzer.BuildReports(ctx, analyzer.BuildConfig{
		Project:              project,
		LookbackWindow:       lookback,
		ServiceAccountFilter: saFilter,
		Debug:                viper.GetBool("debug"),
		IAM:                  iamClient,
		Asset:                assetClient,
		Logging:              loggingCached,
		Monitoring:           monitoringCached,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build reports: %w", err)
	}

	format := output.Format(viper.GetString("output"))
	renderer, err := output.NewRenderer(format, os.Stdout)
	if err != nil {
		return nil, nil, fmt.Errorf("create renderer: %w", err)
	}

	return reports, renderer, nil
}

func resolveServiceAccountFilter(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}

	for c := cmd; c != nil; c = c.Parent() {
		if c.Flags().Lookup("service-account") != nil {
			if v, err := c.Flags().GetString("service-account"); err == nil && v != "" {
				return v
			}
		}
		if c.PersistentFlags().Lookup("service-account") != nil {
			if v, err := c.PersistentFlags().GetString("service-account"); err == nil && v != "" {
				return v
			}
		}
		if c.InheritedFlags().Lookup("service-account") != nil {
			if v, err := c.InheritedFlags().GetString("service-account"); err == nil && v != "" {
				return v
			}
		}
	}

	return ""
}

func resolveExplicitCriticalDays(cmd *cobra.Command) (int, bool) {
	if cmd == nil {
		return 0, false
	}

	for c := cmd; c != nil; c = c.Parent() {
		if f := c.Flags().Lookup("critical-days"); f != nil && f.Changed {
			if v, err := c.Flags().GetInt("critical-days"); err == nil {
				return v, true
			}
		}
		if f := c.PersistentFlags().Lookup("critical-days"); f != nil && f.Changed {
			if v, err := c.PersistentFlags().GetInt("critical-days"); err == nil {
				return v, true
			}
		}
		if f := c.InheritedFlags().Lookup("critical-days"); f != nil && f.Changed {
			if v, err := c.InheritedFlags().GetInt("critical-days"); err == nil {
				return v, true
			}
		}
	}

	return 0, false
}

func loadRoleRegistry() (roles.Registry, error) {
	reg, err := roles.LoadEmbedded()
	if err != nil {
		return nil, fmt.Errorf("load roles registry: %w", err)
	}
	return reg, nil
}

// buildCatalogClient creates a catalog client using the cache dir and TTL from flags.
// The catalog cache uses a 7-day TTL since IAM role definitions rarely change.
func buildCatalogClient() *catalog.Client {
	if viper.GetBool("no_cache") {
		return catalog.New("", 0)
	}
	baseDir, err := cache.DefaultBaseDir()
	if err != nil {
		return catalog.New("", 0)
	}
	return catalog.New(filepath.Join(baseDir, "catalog"), 7*24*time.Hour)
}
