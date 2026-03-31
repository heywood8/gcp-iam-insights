# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`gcp-iam-insights` is a Go CLI tool that analyzes GCP service accounts for security issues:
- **Over-privilege**: accounts bound to broader roles than they need (primitive roles, unused permissions)
- **Dormancy**: accounts inactive beyond configurable thresholds

The tool aggregates data from multiple GCP sources (IAM, Asset Inventory, Cloud Logging, Cloud Monitoring) into a unified report, then runs analyzers to generate actionable findings.

## Build and Development Commands

```bash
# Build binary to dist/gcp-iam-insights
make build

# Run all tests
make test

# Run linter (go vet)
make lint

# Refresh embedded predefined roles registry from GCP IAM API
make fetch-roles

# Clean build artifacts
make clean
```

The binary name is `gcp-iam-insights` despite the repo name being `gcp-iam-role-analyzer`.

## Architecture

### Command Flow
```
CLI (cobra/viper)
  └─> cmd/analyze.go
       └─> buildReportsAndRenderer()
            ├─> auth.Resolve() - credential resolution
            ├─> Create GCP clients (IAM, Asset, Logging, Monitoring)
            ├─> Wrap Logging/Monitoring with cache layer
            ├─> analyzer.BuildReports() - aggregate data from all GCP sources
            └─> output.NewRenderer() - create table/JSON/CSV renderer
       └─> Run analyzers
            ├─> analyzer.AnalyzePrivilege() - detect over-privileged roles
            └─> analyzer.AnalyzeDormancy() - detect inactive accounts
       └─> renderer.Render(findings)
```

### Package Structure

- **`cmd/`** - Cobra CLI commands
  - `root.go` - global flags (project, credentials, cache, lookback-days)
  - `analyze.go` - main analysis command (runs both privilege + dormancy)
  - `privilege.go`, `dormancy.go` - individual analyzer subcommands

- **`pkg/analyzer/`** - Core analysis logic
  - `types.go` - `ServiceAccountReport`, `Finding`, `SAKey` (central data structures)
  - `builder.go` - `BuildReports()` aggregates data from all GCP sources into reports
  - `privilege.go` - detects primitive roles, suggests least-privilege alternatives using set-cover
  - `dormancy.go` - classifies accounts as warn/critical/never-used based on LastUsed

- **`pkg/gcp/`** - GCP API clients
  - `iam.go` - list service accounts, keys, IAM bindings
  - `asset.go` - query Asset Inventory for inherited IAM policies
  - `logging.go` - query audit logs for exercised permissions
  - `monitoring.go` - query Cloud Monitoring for API request counts and authn events
  - `cached.go` - caching wrappers for Logging and Monitoring clients (expensive queries)

- **`pkg/auth/`** - credential resolution (ADC, impersonation, key files)

- **`pkg/cache/`** - disk-based cache with TTL (default 24h) in `~/.cache/gcp-iam-insights/`

- **`pkg/roles/`** - predefined roles registry
  - Embedded `data/predefined_roles.json` (role name → permissions mapping)
  - Greedy set-cover algorithm for suggesting minimal predefined roles

- **`pkg/output/`** - renderers for table, JSON, CSV output formats

- **`tools/fetch-roles/`** - utility to refresh `pkg/roles/data/predefined_roles.json` from GCP IAM API

### Key Data Flow

1. **Report Building** (`analyzer.BuildReports`):
   - List all service accounts (or filter to one)
   - For each SA:
     - Fetch IAM bindings (direct + inherited via Asset Inventory)
     - Fetch keys from IAM API
     - Query Cloud Monitoring for API request counts and authn events per key
     - Query Cloud Logging for audit logs (exercised permissions)
     - Aggregate into `ServiceAccountReport` with `LastUsed` timestamp

2. **Analysis**:
   - `AnalyzePrivilege`: detects primitive roles, compares bound roles to exercised permissions, suggests alternatives
   - `AnalyzeDormancy`: compares `LastUsed` to thresholds (warn/critical days), flags never-used accounts

3. **Output**: findings rendered as table (default), JSON, or CSV

### Caching Strategy

Logging and Monitoring queries are expensive and can hit quota limits. The caching layer:
- Wraps `LoggingClient` and `MonitoringClient` with `cachedLoggingClient` and `cachedMonitoringClient`
- Cache key includes service account identifier AND lookback date (e.g., `logs-sa@example.com-2026-03-01`)
- Default TTL: 24h (configurable via `--cache-ttl`)
- Disable with `--no-cache` flag

IAM and Asset Inventory clients are NOT cached (fast, quota-tolerant).

### Roles Registry

`pkg/roles/data/predefined_roles.json` is an embedded map of GCP predefined role names to their permissions. This enables:
- Offline set-cover algorithm to suggest minimal predefined roles
- No runtime API calls for role definitions

To update: `make fetch-roles` (requires GCP auth with `roles.list` permission)

## Testing

Run all tests: `make test`

Run specific package tests:
```bash
go test ./pkg/cache
go test ./pkg/analyzer -v
```

Tests use standard Go testing, no special frameworks.

## Authentication

The tool supports three auth methods (precedence: impersonation > key file > ADC):
1. **Impersonation**: `--impersonate-service-account sa@project.iam.gserviceaccount.com`
2. **Key file**: `--credentials /path/to/key.json`
3. **ADC**: implicit via `gcloud auth application-default login`

All methods resolve to `google.Options` via `pkg/auth/auth.go`.

## Common Flags

```bash
--project PROJECT_ID                      # Required: GCP project to analyze
--service-account SA_EMAIL                # Optional: analyze single SA instead of all
--output table|json|csv                   # Output format (default: table)
--lookback-days N                         # Days to query logs/metrics (default: 90)
--no-cache                                # Skip disk cache
--cache-ttl 24h                           # Cache TTL (default: 24h)
--credentials /path/to/key.json           # Service account key file
--impersonate-service-account SA_EMAIL    # Impersonate SA via ADC
```

Dormancy-specific (analyze command):
```bash
--warn-days 30        # Days before WARN finding (default: 30)
--critical-days 90    # Days before CRITICAL finding (default: 90)
```

Privilege-specific:
```bash
--suggest-custom-roles    # Suggest custom roles with exact permissions instead of predefined
```

## Git Commit Rules

This repo uses conventional commits. The `commit-msg` hook enforces:
- Format: `<type>(<scope>): <subject>` or `<type>: <subject>`
- Valid types: feat, fix, docs, style, refactor, perf, test, chore, ci, build, revert
- Forbidden text: `NIKITA_LOPATIN`, `homedepot.com`, `REmy`, `Claude`

The `pre-commit` hook runs ESLint on staged JS/TS files (currently no JS/TS in repo, so harmless).
