package crypto_test

import (
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
)

func TestHashVerifyPasswordRoundTrip(t *testing.T) {
	hash, err := crypto.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := crypto.VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("expected correct password to verify")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	hash, err := crypto.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := crypto.VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to be rejected")
	}
}

func TestHashPasswordProducesUniqueSalts(t *testing.T) {
	hash1, err := crypto.HashPassword("same password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	hash2, err := crypto.HashPassword("same password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if hash1 == hash2 {
		t.Fatal("expected two hashes of the same password to differ (random salt)")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	if _, err := crypto.VerifyPassword("x", "not-a-valid-hash"); err == nil {
		t.Fatal("expected VerifyPassword to reject a malformed hash, got nil error")
	}
}
