# GCP IAM Insights

A security analysis tool for Google Cloud Platform service accounts that helps you identify over-privileged and dormant accounts.

## What It Does

GCP IAM Insights scans your GCP project and identifies two major security risks:

1. **Over-Privilege**: Service accounts with excessive permissions
   - Flags primitive roles (Owner, Editor, Viewer) that grant broad access
   - Compares granted permissions to actual usage patterns
   - Suggests least-privilege role alternatives

2. **Dormancy**: Service accounts that are inactive or never used
   - Detects accounts with no activity in the last 30+ days
   - Identifies accounts that have never been used
   - Flags unused service account keys

The tool aggregates data from multiple GCP sources (IAM, Cloud Asset Inventory, Cloud Monitoring, and Cloud Logging) to provide accurate, actionable security findings.

## Features

- **Multi-Source Analysis**: Combines IAM bindings, audit logs, API metrics, and asset inventory
- **Smart Caching**: Caches expensive API queries (24h default) to avoid quota issues
- **Flexible Output**: Table (human-friendly), JSON, or CSV formats
- **Single Account Mode**: Analyze specific service accounts instead of entire projects
- **Custom Role Suggestions**: Can suggest custom roles with exact permissions needed
- **Configurable Thresholds**: Customize warning and critical inactivity periods

## Requirements

- Go 1.25+ (for building from source)
- GCP Project with the following APIs enabled:
  - IAM API
  - Cloud Asset API
  - Cloud Logging API
  - Cloud Monitoring API
- Authentication with one of:
  - Application Default Credentials (ADC)
  - Service account key file
  - Service account impersonation
- Required IAM permissions:
  - `iam.serviceAccounts.list`
  - `iam.serviceAccounts.getIamPolicy`
  - `iam.serviceAccountKeys.list`
  - `cloudasset.assets.searchAllIamPolicies`
  - `logging.logEntries.list`
  - `monitoring.timeSeries.list`

## Installation

### Build from Source

```bash
git clone https://github.com/heywood8/gcp-iam-role-analyzer.git
cd gcp-iam-role-analyzer
make build
```

The binary will be at `dist/gcp-iam-insights`.

### Add to PATH (optional)

```bash
sudo mv dist/gcp-iam-insights /usr/local/bin/
```

## Quick Start

### 1. Authenticate to GCP

```bash
gcloud auth application-default login
```

### 2. Run Analysis

```bash
gcp-iam-insights analyze --project YOUR_PROJECT_ID
```

This will scan all service accounts in your project and display findings in a table.

## Usage Examples

### Analyze All Service Accounts

```bash
gcp-iam-insights analyze --project my-project
```

### Analyze a Specific Service Account

```bash
gcp-iam-insights analyze \
  --project my-project \
  --service-account my-app@my-project.iam.gserviceaccount.com
```

### Export Results to JSON

```bash
gcp-iam-insights analyze \
  --project my-project \
  --output json > findings.json
```

### Custom Inactivity Thresholds

```bash
# Warn after 7 days, critical after 30 days
gcp-iam-insights analyze \
  --project my-project \
  --warn-days 7 \
  --critical-days 30
```

### Suggest Custom Roles

Instead of suggesting predefined roles, suggest custom roles with exact permissions:

```bash
gcp-iam-insights analyze \
  --project my-project \
  --suggest-custom-roles
```

### Extended Lookback Window

```bash
# Look back 180 days for activity
gcp-iam-insights analyze \
  --project my-project \
  --lookback-days 180
```

### Run Without Cache

Useful for getting fresh data or debugging:

```bash
gcp-iam-insights analyze \
  --project my-project \
  --no-cache
```

### Use Service Account Key File

```bash
gcp-iam-insights analyze \
  --project my-project \
  --credentials /path/to/service-account-key.json
```

### Use Service Account Impersonation

```bash
gcp-iam-insights analyze \
  --project my-project \
  --impersonate-service-account analyzer@my-project.iam.gserviceaccount.com
```

## Output Formats

### Table (default)

Human-readable table showing findings with service account, severity, type, and message.

### JSON

Machine-readable JSON array of findings:

```json
[
  {
    "ServiceAccount": "app@project.iam.gserviceaccount.com",
    "Severity": "CRITICAL",
    "Type": "PRIMITIVE_ROLE",
    "Message": "Bound to primitive role: roles/editor",
    "Remediation": "Replace with least-privilege predefined or custom role",
    "Details": {
      "role": "roles/editor"
    }
  }
]
```

### CSV

Spreadsheet-friendly CSV with headers:

```csv
ServiceAccount,Severity,Type,Message,Remediation
app@project.iam.gserviceaccount.com,CRITICAL,PRIMITIVE_ROLE,Bound to primitive role: roles/editor,Replace with least-privilege predefined or custom role
```

## Finding Types

| Type | Description |
|------|-------------|
| `PRIMITIVE_ROLE` | Service account has a primitive role (Owner/Editor/Viewer) |
| `OVER_PRIVILEGE` | Service account has roles with permissions it doesn't use |
| `UNUSED_KEY` | Service account key has never been used for authentication |
| `DORMANT` | Service account hasn't been used in 30+ days (configurable) |
| `NEVER_USED` | Service account has never been used |

## Severity Levels

- **CRITICAL**: Immediate action recommended (primitive roles, 90+ days inactive)
- **WARN**: Review and remediate soon (30+ days inactive, unused keys)
- **INFO**: Informational findings

## How It Works

1. **Discover**: Lists all service accounts in the project (or filters to one)
2. **Gather Data**:
   - IAM bindings (direct and inherited via Cloud Asset Inventory)
   - Service account keys
   - API request metrics from Cloud Monitoring
   - Authentication events per key
   - Audit logs showing exercised permissions
3. **Analyze**:
   - **Privilege Analyzer**: Compares granted roles to exercised permissions, suggests alternatives
   - **Dormancy Analyzer**: Checks last activity timestamp against thresholds
4. **Report**: Outputs actionable findings in your chosen format

## Caching

The tool caches expensive API queries (Cloud Logging and Cloud Monitoring) to:
- Avoid hitting API quota limits
- Speed up repeated runs
- Reduce costs

**Cache location**: `~/.cache/gcp-iam-insights/`  
**Default TTL**: 24 hours  
**Cache keys include**: Service account identifier + lookback date

To clear cache:
```bash
rm -rf ~/.cache/gcp-iam-insights/
```

## Common Scenarios

### Security Audit

Run full analysis and export to CSV for review:

```bash
gcp-iam-insights analyze \
  --project my-project \
  --output csv > audit-$(date +%Y%m%d).csv
```

### Continuous Monitoring

Run daily via cron/Cloud Scheduler and track findings over time:

```bash
0 2 * * * gcp-iam-insights analyze --project my-project --output json > /var/log/iam-findings.json
```

### Cleanup Campaign

Find and fix dormant accounts:

```bash
gcp-iam-insights analyze \
  --project my-project \
  --critical-days 90 \
  --output json | jq '.[] | select(.Type == "NEVER_USED" or .Type == "DORMANT")'
```

### Least Privilege Migration

Identify over-privileged accounts and get remediation suggestions:

```bash
gcp-iam-insights analyze \
  --project my-project \
  --output json | jq '.[] | select(.Type == "PRIMITIVE_ROLE" or .Type == "OVER_PRIVILEGE")'
```

## Troubleshooting

### "API not enabled" errors

Enable required APIs:
```bash
gcloud services enable iam.googleapis.com
gcloud services enable cloudasset.googleapis.com
gcloud services enable logging.googleapis.com
gcloud services enable monitoring.googleapis.com
```

### "Permission denied" errors

Ensure your authenticated account has the required IAM permissions listed in [Requirements](#requirements).

### Slow performance

- Use `--service-account` to analyze one account at a time
- Reduce `--lookback-days` (default: 90)
- Check that caching is enabled (don't use `--no-cache`)

### Quota exceeded

- Enable caching (default: on)
- Increase `--cache-ttl` to reduce API calls
- Reduce `--lookback-days`
- Use `--service-account` to limit scope

## Development

See [CLAUDE.md](./CLAUDE.md) for development documentation.

### Build

```bash
make build
```

### Test

```bash
make test
```

### Lint

```bash
make lint
```

### Update Roles Registry

Refresh the embedded predefined roles from GCP:

```bash
make fetch-roles
```

## License

[Add license information]

## Contributing

[Add contribution guidelines]
