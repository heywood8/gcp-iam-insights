package gcp

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1"
	iamapi "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// ProjectBinding is a role binding at the project level.
type ProjectBinding struct {
	Role    string
	Members []string // e.g. "serviceAccount:sa@project.iam.gserviceaccount.com"
}

// ServiceAccount holds the fields we need from the GCP SA resource.
type ServiceAccount struct {
	Email       string
	UniqueID    string
	DisplayName string
}

// SAKey holds the fields we need from a SA key resource.
type SAKey struct {
	KeyID      string
	CreateTime time.Time
}

// IAMClient is the interface used by analyzers to fetch IAM data.
type IAMClient interface {
	ListServiceAccounts(ctx context.Context, project string) ([]ServiceAccount, error)
	ListProjectBindings(ctx context.Context, project string) ([]ProjectBinding, error)
	ListServiceAccountKeys(ctx context.Context, project, saEmail string) ([]SAKey, error)
}

type realIAMClient struct {
	iamSvc *iamapi.Service
	crmSvc *cloudresourcemanager.Service
}

// NewIAMClient creates a real IAMClient using the provided client options.
func NewIAMClient(ctx context.Context, opts ...option.ClientOption) (IAMClient, error) {
	iamSvc, err := iamapi.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create IAM service: %w", err)
	}
	crmSvc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create CRM service: %w", err)
	}
	return &realIAMClient{iamSvc: iamSvc, crmSvc: crmSvc}, nil
}

func (c *realIAMClient) ListServiceAccounts(ctx context.Context, project string) ([]ServiceAccount, error) {
	var accounts []ServiceAccount
	pageToken := ""
	for {
		resp, err := c.iamSvc.Projects.ServiceAccounts.List("projects/"+project).
			PageToken(pageToken).
			Context(ctx).
			Do()
		if err != nil {
			return nil, fmt.Errorf("list service accounts: %w", err)
		}
		for _, sa := range resp.Accounts {
			accounts = append(accounts, ServiceAccount{
				Email:       sa.Email,
				UniqueID:    sa.UniqueId,
				DisplayName: sa.DisplayName,
			})
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return accounts, nil
}

func (c *realIAMClient) ListProjectBindings(ctx context.Context, project string) ([]ProjectBinding, error) {
	resp, err := c.crmSvc.Projects.GetIamPolicy(project,
		&cloudresourcemanager.GetIamPolicyRequest{}).
		Context(ctx).
		Do()
	if err != nil {
		return nil, fmt.Errorf("get project IAM policy: %w", err)
	}
	bindings := make([]ProjectBinding, 0, len(resp.Bindings))
	for _, b := range resp.Bindings {
		bindings = append(bindings, ProjectBinding{
			Role:    b.Role,
			Members: b.Members,
		})
	}
	return bindings, nil
}

func (c *realIAMClient) ListServiceAccountKeys(ctx context.Context, project, saEmail string) ([]SAKey, error) {
	resp, err := c.iamSvc.Projects.ServiceAccounts.Keys.
		List("projects/"+project+"/serviceAccounts/"+saEmail).
		KeyTypes("USER_MANAGED").
		Context(ctx).
		Do()
	if err != nil {
		return nil, fmt.Errorf("list SA keys for %s: %w", saEmail, err)
	}
	keys := make([]SAKey, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		ct, _ := time.Parse(time.RFC3339, k.ValidAfterTime)
		keyID := k.Name
		for i := len(k.Name) - 1; i >= 0; i-- {
			if k.Name[i] == '/' {
				keyID = k.Name[i+1:]
				break
			}
		}
		keys = append(keys, SAKey{KeyID: keyID, CreateTime: ct})
	}
	return keys, nil
}
