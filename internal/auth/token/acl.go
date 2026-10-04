package token

import "github.com/voidgrid/voidgrid-secrets/internal/model"

// CanAccess reports whether acls grant permission on the resource
// identified by (resourceType, resourceID). A "write" grant implies "read"
// access to the same resource.
func CanAccess(acls []model.TokenACL, resourceType string, resourceID int64, permission string) bool {
	for _, acl := range acls {
		if acl.ResourceType != resourceType || acl.ResourceID != resourceID {
			continue
		}
		if acl.Permission == permission {
			return true
		}
		if acl.Permission == "write" && permission == "read" {
			return true
		}
	}
	return false
}
