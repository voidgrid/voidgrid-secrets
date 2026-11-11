package oidc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
)

// An issuer that was unreachable is tried again later, but not on every
// request, and a client that loads is kept.
func TestProviderLoadsLazilyAndThrottlesRetries(t *testing.T) {
	calls := 0
	failing := &oidc.Provider{Load: func(context.Context) (*oidc.Client, error) {
		calls++
		return nil, errors.New("issuer unreachable")
	}}
	if _, ok := failing.Get(); ok {
		t.Fatal("Get reported a client though Load failed")
	}
	if _, ok := failing.Get(); ok || calls != 1 {
		t.Fatalf("immediate second Get: ok=%v, Load calls=%d, want 1", ok, calls)
	}
	failing.Set(&oidc.Client{})
	if _, ok := failing.Get(); !ok {
		t.Fatal("Get found no client after Set")
	}

	calls = 0
	working := &oidc.Provider{Load: func(context.Context) (*oidc.Client, error) {
		calls++
		return &oidc.Client{}, nil
	}}
	for i := 0; i < 2; i++ {
		if _, ok := working.Get(); !ok {
			t.Fatal("Get found no client though Load succeeded")
		}
	}
	if calls != 1 {
		t.Fatalf("Load calls = %d, want 1", calls)
	}

	if _, ok := (&oidc.Provider{}).Get(); ok {
		t.Fatal("a Provider with no Load and no Set reported a client")
	}
}
