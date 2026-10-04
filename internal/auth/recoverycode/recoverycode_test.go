package recoverycode_test

import (
	"regexp"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/recoverycode"
)

func TestGenerateReturnsCountUniqueCodes(t *testing.T) {
	codes, err := recoverycode.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(codes) != recoverycode.Count {
		t.Fatalf("got %d codes, want %d", len(codes), recoverycode.Count)
	}

	seen := make(map[string]bool, len(codes))
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate code generated: %q", c)
		}
		seen[c] = true
	}
}

func TestGenerateFormatsWithHyphenGroups(t *testing.T) {
	codes, err := recoverycode.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	pattern := regexp.MustCompile(`^[A-Z2-7]{5}(-[A-Z2-7]{5})*-[A-Z2-7]{1,5}$`)
	for _, c := range codes {
		if !pattern.MatchString(c) {
			t.Fatalf("code %q doesn't match expected format", c)
		}
	}
}
