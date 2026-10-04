package crypto_test

import (
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
)

func TestHashTokenIsDeterministic(t *testing.T) {
	h1 := crypto.HashToken("vgs_abc123")
	h2 := crypto.HashToken("vgs_abc123")
	if h1 != h2 {
		t.Fatalf("HashToken is not deterministic: %q != %q", h1, h2)
	}
}

func TestVerifyTokenHashRoundTrip(t *testing.T) {
	hash := crypto.HashToken("vgs_abc123")
	if !crypto.VerifyTokenHash("vgs_abc123", hash) {
		t.Fatal("expected matching token to verify")
	}
}

func TestVerifyTokenHashRejectsWrongToken(t *testing.T) {
	hash := crypto.HashToken("vgs_abc123")
	if crypto.VerifyTokenHash("vgs_different", hash) {
		t.Fatal("expected mismatched token to be rejected")
	}
}
