package output

import "strings"

// shortenSAName strips the @<project>.iam.gserviceaccount.com suffix from SA emails.
func shortenSAName(email string) string {
	if idx := strings.Index(email, "@"); idx != -1 {
		return email[:idx]
	}
	return email
}
