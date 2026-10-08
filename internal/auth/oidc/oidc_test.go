package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
)

// New performs real OIDC discovery and so can't be meaningfully tested
// against a happy path without a live or faked IdP (see the package doc
// comment). This covers what's verifiable without one: a bad/unreachable
// issuer must fail fast with an error, not hang or panic.
func TestNewFailsFastOnUnreachableIssuer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := oidc.New(ctx, oidc.Config{
		Issuer:       "http://127.0.0.1:1/does-not-exist",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "http://127.0.0.1:8780/auth/oidc/callback",
	})
	if err == nil {
		t.Fatal("expected New to fail for an unreachable issuer")
	}
}

func TestStateIsNonEmptyAndUnique(t *testing.T) {
	a := oidc.State()
	b := oidc.State()
	if a == "" || b == "" {
		t.Fatal("expected non-empty state values")
	}
	if a == b {
		t.Fatal("expected two calls to State to produce different values")
	}
}
