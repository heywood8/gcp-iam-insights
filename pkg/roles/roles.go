package roles

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed data/predefined_roles.json
var embeddedRolesJSON []byte

// Registry maps role name (e.g. "roles/storage.objectViewer") to its set of
// included IAM permissions.
type Registry map[string][]string

// LoadEmbedded parses the bundled predefined_roles.json into a Registry.
func LoadEmbedded() (Registry, error) {
	var r Registry
	if err := json.Unmarshal(embeddedRolesJSON, &r); err != nil {
		return nil, fmt.Errorf("parse embedded roles: %w", err)
	}
	return r, nil
}

// FindMinimalRoles returns the smallest set of predefined roles whose combined
// permissions cover all requested permissions. It also returns any permissions
// that could not be covered by any known predefined role.
//
// Algorithm: greedy set cover — at each step, pick the role that covers the
// most uncovered permissions. This is a well-known approximation for the
// NP-hard set cover problem and produces good results for the typical case.
func (reg Registry) FindMinimalRoles(permissions []string) (roleNames []string, uncovered []string) {
	needed := make(map[string]bool, len(permissions))
	for _, p := range permissions {
		needed[p] = true
	}

	for len(needed) > 0 {
		bestRole := ""
		bestCoverage := 0

		for roleName, rolePerms := range reg {
			coverage := 0
			for _, p := range rolePerms {
				if needed[p] {
					coverage++
				}
			}
			if coverage > bestCoverage ||
				(coverage == bestCoverage && roleName < bestRole) { // tie-break alphabetically for determinism
				bestCoverage = coverage
				bestRole = roleName
			}
		}

		if bestCoverage == 0 {
			// No role covers any remaining permission — they are uncoverable.
			for p := range needed {
				uncovered = append(uncovered, p)
			}
			break
		}

		roleNames = append(roleNames, bestRole)
		for _, p := range reg[bestRole] {
			delete(needed, p)
		}
	}

	sort.Strings(roleNames)
	sort.Strings(uncovered)
	return roleNames, uncovered
}
