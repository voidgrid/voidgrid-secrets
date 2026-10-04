package session_test

import (
	"strings"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
)

func TestGenerateHasPrefixAndIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, err := session.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !strings.HasPrefix(tok, session.Prefix) {
			t.Fatalf("token %q missing prefix %q", tok, session.Prefix)
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = true
	}
}
