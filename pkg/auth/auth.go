package auth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// Config holds the credential configuration supplied via CLI flags.
type Config struct {
	// ImpersonateServiceAccount is the SA email to impersonate via ADC.
	// Takes priority over CredentialsFile.
	ImpersonateServiceAccount string

	// CredentialsFile is a path to a service account JSON key file.
	CredentialsFile string
}

// Resolve returns Google API client options using the highest-priority credential
// available: impersonation > key file > ADC.
func Resolve(ctx context.Context, cfg Config, scopes ...string) ([]option.ClientOption, error) {
	if cfg.ImpersonateServiceAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: cfg.ImpersonateServiceAccount,
			Scopes:          scopes,
		})
		if err != nil {
			return nil, fmt.Errorf("impersonate %s: %w", cfg.ImpersonateServiceAccount, err)
		}
		return []option.ClientOption{option.WithTokenSource(ts)}, nil
	}

	if cfg.CredentialsFile != "" {
		return []option.ClientOption{option.WithCredentialsFile(cfg.CredentialsFile)}, nil
	}

	// ADC fallback — uses GOOGLE_APPLICATION_CREDENTIALS env var or gcloud ADC.
	creds, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, fmt.Errorf("find application default credentials: %w", err)
	}
	return []option.ClientOption{option.WithCredentials(creds)}, nil
}
