package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/heywood8/gcp-iam-insights/pkg/gcp"
)

// BuildConfig holds all dependencies needed to build ServiceAccountReports.
type BuildConfig struct {
	Project              string
	LookbackWindow       time.Duration
	ServiceAccountFilter string // if set, only analyze this SA email
	Debug                bool   // if true, log verbose per-SA details

	IAM        gcp.IAMClient
	Asset      gcp.AssetClient
	Logging    gcp.LoggingClient
	Monitoring gcp.MonitoringClient
}

// BuildReports fetches data from all GCP sources and constructs a
// ServiceAccountReport for each service account in the project.
func BuildReports(ctx context.Context, cfg BuildConfig) ([]ServiceAccountReport, error) {
	// 1. List service accounts.
	fmt.Fprintf(os.Stderr, "Discovering service accounts in project %s...\n", cfg.Project)
	sas, err := cfg.IAM.ListServiceAccounts(ctx, cfg.Project)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}

	// Filter if needed and report count.
	accountsToProcess := sas
	if cfg.ServiceAccountFilter != "" {
		filtered := []gcp.ServiceAccount{}
		for _, sa := range sas {
			if sa.Email == cfg.ServiceAccountFilter {
				filtered = append(filtered, sa)
			}
		}
		accountsToProcess = filtered
		if len(filtered) == 0 {
			fmt.Fprintf(os.Stderr, "No service accounts match filter: %s\n", cfg.ServiceAccountFilter)
			return nil, nil
		}
		fmt.Fprintf(os.Stderr, "Found 1 service account matching filter\n")
	} else {
		fmt.Fprintf(os.Stderr, "Found %d service accounts\n", len(accountsToProcess))
	}

	// 2. Get project-level IAM bindings + inherited bindings from Asset Inventory (in parallel).
	fmt.Fprintf(os.Stderr, "Fetching IAM bindings...\n")
	var projectBindings, assetBindings []gcp.ProjectBinding
	var projectErr, assetErr error
	var bindingsWg sync.WaitGroup

	bindingsWg.Add(2)
	go func() {
		defer bindingsWg.Done()
		projectBindings, projectErr = cfg.IAM.ListProjectBindings(ctx, cfg.Project)
	}()
	go func() {
		defer bindingsWg.Done()
		assetBindings, assetErr = cfg.Asset.SearchIAMPolicies(ctx, cfg.Project)
	}()
	bindingsWg.Wait()

	if projectErr != nil {
		return nil, fmt.Errorf("list project bindings: %w", projectErr)
	}
	if assetErr != nil {
		return nil, fmt.Errorf("search asset IAM policies: %w", assetErr)
	}
	fmt.Fprintf(os.Stderr, "Found %d project-level binding(s) and %d inherited binding(s) from Asset Inventory\n",
		len(projectBindings), len(assetBindings))

	allBindings := make([]gcp.ProjectBinding, 0, len(projectBindings)+len(assetBindings))
	allBindings = append(allBindings, projectBindings...)
	allBindings = append(allBindings, assetBindings...)

	// Build a map from SA email → set of bound roles.
	rolesBySA := map[string]map[string]bool{}
	for _, b := range allBindings {
		for _, member := range b.Members {
			email := member
			const prefix = "serviceAccount:"
			if len(member) > len(prefix) && member[:len(prefix)] == prefix {
				email = member[len(prefix):]
			}
			if rolesBySA[email] == nil {
				rolesBySA[email] = map[string]bool{}
			}
			rolesBySA[email][b.Role] = true
		}
	}

	since := time.Now().Add(-cfg.LookbackWindow)
	reports := make([]ServiceAccountReport, len(accountsToProcess))

	fmt.Fprintf(os.Stderr, "\nAnalyzing service accounts (lookback: %d days)...\n", int(cfg.LookbackWindow.Hours()/24))

	// Fetch audit logs in a single batched query for all SAs to avoid quota exhaustion
	fmt.Fprintf(os.Stderr, "Fetching audit logs for %d service account(s) (batched query)...\n", len(accountsToProcess))
	saEmails := make([]string, len(accountsToProcess))
	for i, sa := range accountsToProcess {
		saEmails[i] = sa.Email
	}
	auditLogsBySA := map[string][]gcp.AuditEntry{}
	if logsBatch, err := cfg.Logging.QueryAuditLogsBatch(ctx, cfg.Project, saEmails, since); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not query audit logs in batch: %v\n", err)
	} else {
		auditLogsBySA = logsBatch
		totalLogs := 0
		for _, logs := range logsBatch {
			totalLogs += len(logs)
		}
		fmt.Fprintf(os.Stderr, "Found %d total audit log entries across %d service accounts\n", totalLogs, len(accountsToProcess))
	}

	// Process service accounts in parallel with worker pool
	const maxWorkers = 10
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup
	logBuffers := make([]*bytes.Buffer, len(accountsToProcess))

	for idx, sa := range accountsToProcess {
		wg.Add(1)
		go func(i int, account gcp.ServiceAccount) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire worker slot
			defer func() { <-sem }() // Release worker slot

			// Buffer logs for this SA to print in order later
			buf := &bytes.Buffer{}
			logBuffers[i] = buf
			fmt.Fprintf(buf, "[%d/%d] Processing %s\n", i+1, len(accountsToProcess), account.Email)

			// 3. Collect bound roles.
			var roles []string
			for role := range rolesBySA[account.Email] {
				roles = append(roles, role)
			}

			// 4. Fetch SA keys.
			gcpKeys, err := cfg.IAM.ListServiceAccountKeys(ctx, cfg.Project, account.Email)
			if err != nil {
				fmt.Fprintf(buf, "  error: list keys for %s: %v\n", account.Email, err)
				return
			}
			if cfg.Debug {
				fmt.Fprintf(buf, "  - Found %d key(s)\n", len(gcpKeys))
			}

			// 5. Fetch Cloud Monitoring metrics (non-fatal: log warning and continue with empty data).
			if cfg.Debug {
				fmt.Fprintf(buf, "  - Querying Cloud Monitoring metrics...\n")
			}

			// API usage per service from metrics
			apiUsageFromMetrics := map[string]int64{}
			if usage, err := cfg.Monitoring.GetAPIUsagePerService(ctx, cfg.Project, account.UniqueID, since); err != nil {
				if cfg.Debug {
					fmt.Fprintf(buf, "  warning: could not fetch API usage metrics: %v\n", err)
				}
			} else {
				apiUsageFromMetrics = usage
				if cfg.Debug && len(usage) > 0 {
					fmt.Fprintf(buf, "  - Found API usage for %d service(s) from metrics\n", len(usage))
				}
			}

			// Authn events per key
			authnPerKey := map[string]int64{}
			if authn, err := cfg.Monitoring.GetAuthnEventsPerKey(ctx, cfg.Project, account.UniqueID, since); err != nil {
				if cfg.Debug {
					fmt.Fprintf(buf, "  warning: could not fetch authn event metrics: %v\n", err)
				}
			} else {
				authnPerKey = authn
			}

			// Merge authn events into keys.
			saKeys := make([]SAKey, 0, len(gcpKeys))
			for _, k := range gcpKeys {
				saKeys = append(saKeys, SAKey{
					KeyID:       k.KeyID,
					CreateTime:  k.CreateTime,
					AuthnEvents: authnPerKey[k.KeyID],
				})
			}

			// 6. Use pre-fetched audit logs from batch query.
			logEntries := auditLogsBySA[account.Email]
			if cfg.Debug && len(logEntries) > 0 {
				fmt.Fprintf(buf, "  - Found %d audit log entries\n", len(logEntries))
			}

			// Process audit logs: extract permissions, API activity, and last used timestamp.
			permSet := map[string]bool{}
			apiCallCountFromLogs := map[string]int64{}
			var latestLog *time.Time
			for _, entry := range logEntries {
				if entry.MethodName != "" {
					permSet[entry.MethodName] = true
				}
				if entry.ServiceName != "" {
					apiCallCountFromLogs[entry.ServiceName]++
				}
				t := entry.Timestamp
				if latestLog == nil || t.After(*latestLog) {
					latestLog = &t
				}
			}

			var exercisedPerms []string
			for p := range permSet {
				exercisedPerms = append(exercisedPerms, p)
			}

			// Combine API usage from metrics and logs. Prefer metrics (more complete), supplement with logs.
			activeAPIs := map[string]int64{}
			for svc, count := range apiUsageFromMetrics {
				activeAPIs[svc] = count
			}
			for svc, count := range apiCallCountFromLogs {
				if activeAPIs[svc] == 0 {
					activeAPIs[svc] = count
				}
			}

			// LastUsed: prefer audit log timestamp (more precise), but if metrics show activity and no logs, use now.
			var lastUsed *time.Time
			if latestLog != nil {
				lastUsed = latestLog
			} else if len(apiUsageFromMetrics) > 0 || len(authnPerKey) > 0 {
				// Metrics show activity but no audit logs - service account is active but logs incomplete
				now := time.Now()
				lastUsed = &now
			}

			// Write to pre-allocated slice at this goroutine's index
			reports[i] = ServiceAccountReport{
				Email:          account.Email,
				UniqueID:       account.UniqueID,
				DisplayName:    account.DisplayName,
				Roles:          roles,
				Keys:           saKeys,
				ActiveAPIs:     activeAPIs,
				ExercisedPerms: exercisedPerms,
				LastUsed:       lastUsed,
				LookbackWindow: cfg.LookbackWindow,
			}
		}(idx, sa)
	}

	// Wait for all workers to complete
	wg.Wait()

	// Print buffered logs in order
	for i, buf := range logBuffers {
		if buf != nil {
			os.Stderr.Write(buf.Bytes())
		} else {
			fmt.Fprintf(os.Stderr, "[%d/%d] Processing failed (no log buffer)\n", i+1, len(accountsToProcess))
		}
	}

	fmt.Fprintf(os.Stderr, "\nCompleted analysis of %d service account(s)\n\n", len(reports))
	return reports, nil
}
