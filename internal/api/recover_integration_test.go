package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
)

type recoverStart struct {
	ResetToken string `json:"reset_token"`
	TOTPSecret string `json:"totp_secret"`
}

func startRecovery(t *testing.T, e env, code string) (int, recoverStart) {
	t.Helper()
	rec := doJSON(t, e.handler, http.MethodPost, "/api/v1/recover", fmt.Sprintf(`{"code":%q}`, code), nil)
	var body recoverStart
	_ = json.NewDecoder(rec.Body).Decode(&body)
	return rec.Code, body
}

func completeRecovery(t *testing.T, e env, s recoverStart, password string) (int, []string) {
	t.Helper()
	code, err := totp.GenerateCode(s.TOTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := doJSON(t, e.handler, http.MethodPost, "/api/v1/recover/complete",
		fmt.Sprintf(`{"reset_token":%q,"new_password":%q,"totp_code":%q}`, s.ResetToken, password, code), nil)
	var body struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&body)
	return rec.Code, body.RecoveryCodes
}

func TestRecoveryCodeResetsTheAccount(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	oldSession := ownerCookie(t, e)
	if err := e.recoveryCodes.ReplaceForUser(ctx, 1, []string{crypto.HashToken("ABCDE-FGHIJ-KLMNO-PQRST-UV")}); err != nil {
		t.Fatal(err)
	}

	if code, _ := startRecovery(t, e, "WRONG-CODE"); code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", code)
	}
	// Typed in lowercase without hyphens still matches.
	code, started := startRecovery(t, e, "abcdefghijklmnopqrstuv")
	if code != http.StatusOK || started.ResetToken == "" || started.TOTPSecret == "" {
		t.Fatalf("start: %d %+v", code, started)
	}
	if code, _ := startRecovery(t, e, "ABCDE-FGHIJ-KLMNO-PQRST-UV"); code != http.StatusUnauthorized {
		t.Fatalf("recovery code worked twice: %d", code)
	}

	if code, _ := completeRecovery(t, e, started, "too-short"); code != http.StatusBadRequest {
		t.Fatalf("weak password: %d", code)
	}
	code, newCodes := completeRecovery(t, e, started, "a brand new long password")
	if code != http.StatusOK || len(newCodes) == 0 {
		t.Fatalf("complete: %d %v", code, newCodes)
	}
	if code, _ := completeRecovery(t, e, started, "a brand new long password"); code != http.StatusUnauthorized {
		t.Fatalf("reset finished twice: %d", code)
	}

	// The old session is gone; the new password and TOTP work.
	if rec := doJSON(t, e.handler, http.MethodGet, "/api/v1/tokens", "", oldSession); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old session still valid: %d", rec.Code)
	}
	totpCode, _ := totp.GenerateCode(started.TOTPSecret, time.Now())
	rec := doJSON(t, e.handler, http.MethodPost, "/api/v1/auth/login",
		fmt.Sprintf(`{"username":"owner","password":"a brand new long password","totp_code":%q}`, totpCode), nil)
	if rec.Code >= 300 || !strings.Contains(rec.Header().Get("Set-Cookie"), "vgs_session=") {
		t.Fatalf("login with new credentials: %d %s", rec.Code, rec.Body.String())
	}
	// And one of the new recovery codes starts a reset.
	if code, _ := startRecovery(t, e, newCodes[0]); code != http.StatusOK {
		t.Fatalf("new recovery code: %d", code)
	}
}

func TestBreakGlassCodeResetsTheAccountOnce(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	ownerCookie(t, e)

	code, _, err := e.recovery.IssueBreakGlass(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status, started := startRecovery(t, e, code)
	if status != http.StatusOK {
		t.Fatalf("break-glass start: %d", status)
	}
	if status, _ := completeRecovery(t, e, started, "another long new password"); status != http.StatusOK {
		t.Fatalf("break-glass complete: %d", status)
	}
	if status, _ := startRecovery(t, e, code); status != http.StatusUnauthorized {
		t.Fatalf("break-glass code worked twice: %d", status)
	}
}
