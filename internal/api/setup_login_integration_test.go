package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
)

func doJSON(t *testing.T, handler http.Handler, method, path string, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestWizardLocksOutSecretsUntilSetupComplete(t *testing.T) {
	e := newEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1", nil)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestWizardLocksOutLoginUntilSetupComplete(t *testing.T) {
	e := newEnv(t, false)

	rec := doJSON(t, e.handler, http.MethodPost, "/api/v1/auth/login", `{"username":"admin","password":"x","totp_code":"123456"}`, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestWizardLocksOutTokensUntilSetupComplete(t *testing.T) {
	e := newEnv(t, false)

	rec := doJSON(t, e.handler, http.MethodGet, "/api/v1/tokens", "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestSetupStatusAlwaysReachable(t *testing.T) {
	e := newEnv(t, false)

	rec := doJSON(t, e.handler, http.MethodGet, "/api/v1/setup/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Complete bool `json:"complete"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Complete {
		t.Fatal("expected setup to be incomplete on a fresh environment")
	}
}

func TestFullSetupAndLoginFlow(t *testing.T) {
	e := newEnv(t, false)

	initRec := doJSON(t, e.handler, http.MethodPost, "/api/v1/setup/password/init",
		`{"setup_token":"vgs_setup_test","username":"admin","password":"correct horse battery staple"}`, nil)
	if initRec.Code != http.StatusOK {
		t.Fatalf("init status = %d, want %d; body=%s", initRec.Code, http.StatusOK, initRec.Body.String())
	}
	var initBody struct {
		Secret          string `json:"secret"`
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.NewDecoder(initRec.Body).Decode(&initBody); err != nil {
		t.Fatalf("decode init response: %v", err)
	}
	if initBody.Secret == "" {
		t.Fatal("expected a non-empty TOTP secret")
	}

	// Setup is not complete yet: secrets, login, and admin must still be
	// locked out.
	statusRec := doJSON(t, e.handler, http.MethodGet, "/api/v1/setup/status", "", nil)
	var status struct {
		Complete bool `json:"complete"`
	}
	_ = json.NewDecoder(statusRec.Body).Decode(&status)
	if status.Complete {
		t.Fatal("expected setup to still be incomplete before TOTP confirmation")
	}

	code, err := totp.GenerateCode(initBody.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	confirmRec := doJSON(t, e.handler, http.MethodPost, "/api/v1/setup/password/confirm",
		fmt.Sprintf(`{"setup_token":"vgs_setup_test","username":"admin","code":%q}`, code), nil)
	if confirmRec.Code != http.StatusOK && confirmRec.Code != http.StatusNoContent {
		t.Fatalf("confirm status = %d, want 200/204; body=%s", confirmRec.Code, confirmRec.Body.String())
	}

	// Setup endpoints are now locked out in the other direction.
	reinitRec := doJSON(t, e.handler, http.MethodPost, "/api/v1/setup/password/init",
		`{"setup_token":"vgs_setup_test","username":"admin2","password":"another password here"}`, nil)
	if reinitRec.Code != http.StatusConflict {
		t.Fatalf("re-init status = %d, want %d", reinitRec.Code, http.StatusConflict)
	}

	// Now log in.
	loginRec := doJSON(t, e.handler, http.MethodPost, "/api/v1/auth/login",
		fmt.Sprintf(`{"username":"admin","password":"correct horse battery staple","totp_code":%q}`, code), nil)
	if loginRec.Code != http.StatusNoContent && loginRec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200/204; body=%s", loginRec.Code, loginRec.Body.String())
	}
	setCookie := loginRec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, gosession.CookieName+"=") {
		t.Fatalf("expected Set-Cookie to contain %s=, got %q", gosession.CookieName, setCookie)
	}

	// The account can now manage tokens.
	cookieParts := strings.SplitN(strings.TrimPrefix(setCookie, gosession.CookieName+"="), ";", 2)
	sessionCookie := &http.Cookie{Name: gosession.CookieName, Value: cookieParts[0]} //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here

	tokensRec := doJSON(t, e.handler, http.MethodGet, "/api/v1/tokens", "", sessionCookie)
	if tokensRec.Code != http.StatusOK {
		t.Fatalf("tokens status = %d, want %d; body=%s", tokensRec.Code, http.StatusOK, tokensRec.Body.String())
	}

	// Logout clears the cookie.
	logoutRec := doJSON(t, e.handler, http.MethodPost, "/api/v1/auth/logout", "", sessionCookie)
	if logoutRec.Code != http.StatusNoContent && logoutRec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200/204; body=%s", logoutRec.Code, logoutRec.Body.String())
	}
	clearedCookie := logoutRec.Header().Get("Set-Cookie")
	if !strings.Contains(clearedCookie, "Max-Age=0") {
		t.Fatalf("expected logout Set-Cookie to clear the cookie (Max-Age=0), got %q", clearedCookie)
	}
}

func TestLoginRejectsWrongTOTPAfterSetup(t *testing.T) {
	e := newEnv(t, false)

	initRec := doJSON(t, e.handler, http.MethodPost, "/api/v1/setup/password/init",
		`{"setup_token":"vgs_setup_test","username":"admin","password":"correct horse battery staple"}`, nil)
	var initBody struct {
		Secret string `json:"secret"`
	}
	_ = json.NewDecoder(initRec.Body).Decode(&initBody)

	code, _ := totp.GenerateCode(initBody.Secret, time.Now())
	doJSON(t, e.handler, http.MethodPost, "/api/v1/setup/password/confirm",
		fmt.Sprintf(`{"setup_token":"vgs_setup_test","username":"admin","code":%q}`, code), nil)

	loginRec := doJSON(t, e.handler, http.MethodPost, "/api/v1/auth/login",
		`{"username":"admin","password":"correct horse battery staple","totp_code":"000000"}`, nil)
	if loginRec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", loginRec.Code, http.StatusUnauthorized, loginRec.Body.String())
	}
}

func TestMachineTokenCannotManageTokens(t *testing.T) {
	e := newEnv(t, true)

	plaintext, _, err := e.tokens.Create(t.Context(), "some-machine", nil)
	if err != nil {
		t.Fatalf("tokens.Create: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	// Token management is session-only: a bearer token isn't even a form
	// of authentication there, so this is 401, not 403.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestSetupRequiresTheSetupToken(t *testing.T) {
	e := newEnv(t, false)

	for _, c := range []struct{ path, body string }{
		{"/api/v1/setup/password/init", `{"setup_token":"wrong","username":"admin","password":"correct horse battery staple"}`},
		{"/api/v1/setup/password/confirm", `{"setup_token":"wrong","username":"admin","code":"123456"}`},
		// An unreachable issuer would give 400 if discovery ran first; 403
		// shows the token is checked before the server contacts anything.
		{"/api/v1/setup/oidc", `{"setup_token":"wrong","issuer":"http://127.0.0.1:1","client_id":"x","client_secret":"x","redirect_uri":"https://app.example/cb"}`},
	} {
		if rec := doJSON(t, e.handler, http.MethodPost, c.path, c.body, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s with wrong token: status = %d, want 403; body=%s", c.path, rec.Code, rec.Body.String())
		}
	}
	if _, err := e.users.Get(context.Background()); err == nil {
		t.Fatal("an account exists after refused setup")
	}
}
