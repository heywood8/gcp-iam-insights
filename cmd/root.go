package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "gcp-iam-insights",
	Short: "Analyze GCP service accounts for over-privilege and dormancy",
	Long: `gcp-iam-insights analyzes service accounts in a GCP project for:
  - Over-privilege: accounts bound to broader roles than they need
  - Dormancy: accounts inactive beyond configurable thresholds`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().String("project", "", "GCP project ID to analyze (required)")
	rootCmd.PersistentFlags().String("output", "table", "Output format: table, json, csv")
	rootCmd.PersistentFlags().String("credentials", "", "Path to service account key file")
	rootCmd.PersistentFlags().String("impersonate-service-account", "", "Service account email to impersonate via ADC")
	rootCmd.PersistentFlags().Bool("no-cache", false, "Skip cache and always fetch fresh data")
	rootCmd.PersistentFlags().Duration("cache-ttl", 24*time.Hour, "Cache TTL duration")
	rootCmd.PersistentFlags().Int("lookback-days", 90, "Number of days to look back for metrics and audit logs")

	viper.BindPFlag("project", rootCmd.PersistentFlags().Lookup("project"))
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("credentials", rootCmd.PersistentFlags().Lookup("credentials"))
	viper.BindPFlag("impersonate_service_account", rootCmd.PersistentFlags().Lookup("impersonate-service-account"))
	viper.BindPFlag("no_cache", rootCmd.PersistentFlags().Lookup("no-cache"))
	viper.BindPFlag("cache_ttl", rootCmd.PersistentFlags().Lookup("cache-ttl"))
	viper.BindPFlag("lookback_days", rootCmd.PersistentFlags().Lookup("lookback-days"))
}
