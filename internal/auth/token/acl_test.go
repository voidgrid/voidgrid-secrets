package token_test

import (
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

func TestCanAccessExactPermission(t *testing.T) {
	acls := []model.TokenGrant{
		{SecretID: 1, Permission: "read"},
	}
	if !token.CanAccess(acls, 1, "read") {
		t.Fatal("expected read access to be granted")
	}
	if token.CanAccess(acls, 1, "write") {
		t.Fatal("expected write access to be denied for a read-only grant")
	}
}

func TestCanAccessWriteImpliesRead(t *testing.T) {
	acls := []model.TokenGrant{
		{SecretID: 1, Permission: "write"},
	}
	if !token.CanAccess(acls, 1, "read") {
		t.Fatal("expected write grant to imply read access")
	}
	if !token.CanAccess(acls, 1, "write") {
		t.Fatal("expected write access to be granted")
	}
}

func TestCanAccessDeniesOtherResources(t *testing.T) {
	acls := []model.TokenGrant{
		{SecretID: 1, Permission: "write"},
	}
	if token.CanAccess(acls, 2, "read") {
		t.Fatal("expected access to a different secret ID to be denied")
	}
}
