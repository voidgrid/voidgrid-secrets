package totp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	gototp "github.com/voidgrid/voidgrid-secrets/internal/auth/totp"
)

func TestGenerateAndValidateRoundTrip(t *testing.T) {
	secret, uri, err := gototp.Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if secret == "" {
		t.Fatal("expected a non-empty secret")
	}
	if !strings.Contains(uri, gototp.Issuer) {
		t.Fatalf("expected provisioning URI to contain issuer %q, got %q", gototp.Issuer, uri)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if !gototp.Validate(code, secret) {
		t.Fatal("expected a freshly generated code to validate")
	}
}

func TestValidateRejectsWrongCode(t *testing.T) {
	secret, _, err := gototp.Generate("bob")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if gototp.Validate("000000", secret) {
		t.Fatal("expected an arbitrary code to be rejected (astronomically unlikely to collide)")
	}
}
