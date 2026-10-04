package token_test

import (
	"strings"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/token"
)

func TestGenerateHasPrefixAndIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, err := token.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !strings.HasPrefix(tok, token.Prefix) {
			t.Fatalf("token %q missing prefix %q", tok, token.Prefix)
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = true
	}
}
