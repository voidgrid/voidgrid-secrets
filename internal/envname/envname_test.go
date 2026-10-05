package envname_test

import (
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/envname"
)

func TestDerive(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // secret *names* as test inputs, not credentials
		"db-password":    "DB_PASSWORD",
		"API_KEY":        "API_KEY",
		"smtp.relay pw":  "SMTP_RELAY_PW",
		"2fa-seed":       "_2FA_SEED",
		"grafana/admin":  "GRAFANA_ADMIN",
		"café-token":     "CAF__TOKEN",
		"already_lower1": "ALREADY_LOWER1",
	}
	for in, want := range cases {
		if got := envname.Derive(in); got != want {
			t.Errorf("Derive(%q) = %q, want %q", in, got, want)
		}
		if !envname.Valid(envname.Derive(in)) {
			t.Errorf("Derive(%q) produced an invalid name %q", in, envname.Derive(in))
		}
	}
}

func TestValid(t *testing.T) {
	for _, ok := range []string{"DB_PASSWORD", "_X", "A1", "POSTGRES_PASSWORD"} {
		if !envname.Valid(ok) {
			t.Errorf("Valid(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "1ABC", "db_password", "DB-PASSWORD", "A B", "A=B"} {
		if envname.Valid(bad) {
			t.Errorf("Valid(%q) = true, want false", bad)
		}
	}
}
