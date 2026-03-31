// tools/fetch-roles/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"google.golang.org/api/iam/v1"
)

func main() {
	ctx := context.Background()
	svc, err := iam.NewService(ctx)
	if err != nil {
		log.Fatalf("create IAM service: %v", err)
	}

	result := map[string][]string{}
	pageToken := ""
	for {
		req := svc.Roles.List().View("FULL").PageSize(1000)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		resp, err := req.Do()
		if err != nil {
			log.Fatalf("list roles: %v", err)
		}
		for _, r := range resp.Roles {
			result[r.Name] = r.IncludedPermissions
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}

	outPath := "pkg/roles/data/predefined_roles.json"
	if err := os.MkdirAll("pkg/roles/data", 0o755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		log.Fatalf("write: %v", err)
	}
	fmt.Printf("wrote %d roles to %s\n", len(result), outPath)
}
