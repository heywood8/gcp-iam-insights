package gcp

import (
	"context"
	"fmt"

	asset "cloud.google.com/go/asset/apiv1"
	assetpb "cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// AssetClient is the interface for Cloud Asset Inventory queries.
type AssetClient interface {
	SearchIAMPolicies(ctx context.Context, project string) ([]ProjectBinding, error)
}

type realAssetClient struct {
	client *asset.Client
}

// NewAssetClient creates a real AssetClient.
func NewAssetClient(ctx context.Context, opts ...option.ClientOption) (AssetClient, error) {
	c, err := asset.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create asset client: %w", err)
	}
	return &realAssetClient{client: c}, nil
}

func (c *realAssetClient) SearchIAMPolicies(ctx context.Context, project string) ([]ProjectBinding, error) {
	req := &assetpb.SearchAllIamPoliciesRequest{
		Scope: "projects/" + project,
	}
	it := c.client.SearchAllIamPolicies(ctx, req)

	var bindings []ProjectBinding
	for {
		result, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iterate IAM policies: %w", err)
		}
		if result.Policy == nil {
			continue
		}
		for _, b := range result.Policy.Bindings {
			bindings = append(bindings, ProjectBinding{
				Role:    b.Role,
				Members: b.Members,
			})
		}
	}
	return bindings, nil
}
