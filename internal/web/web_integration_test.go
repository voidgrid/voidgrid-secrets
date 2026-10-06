package web_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/recoverycode"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	gototp "github.com/voidgrid/voidgrid-secrets/internal/auth/totp"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/recovery"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
	"github.com/voidgrid/voidgrid-secrets/internal/web"
)

// env is a full, real stack (rqlite + storage + web router) for exercising
// the UI end-to-end.
type env struct {
	handler    http.Handler
	users      *storage.UserRepo
	sessions   *storage.SessionRepo
	secrets    *storage.SecretRepo
	authConfig *storage.AuthConfigRepo
}

const testSetupToken = "vgs_setup_test" //nolint:gosec // fake test fixture, not a real credential

func newEnv(t *testing.T) env {
	t.Helper()

	if _, err := exec.LookPath("rqlited"); err != nil {
		t.Skip("rqlited not found in PATH; skipping integration test")
	}

	httpPort := freePort(t)
	raftPort := freePort(t)
	dataDir := t.TempDir()
	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	cmd := exec.Command("rqlited", //nolint:gosec // fixed binary name + test-generated args
		"-fk",
		"-http-addr", httpAddr,
		"-raft-addr", fmt.Sprintf("127.0.0.1:%d", raftPort),
		dataDir,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rqlited: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	baseURL := "http://" + httpAddr
	waitForReady(t, baseURL)

	db, err := storage.Open(baseURL)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	rootKey := make([]byte, crypto.KeySize)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	tokenRepo := storage.NewTokenRepo(db)
	userRepo := storage.NewUserRepo(db, rootKey)
	sessionRepo := storage.NewSessionRepo(db)
	authConfigRepo := storage.NewAuthConfigRepo(db, rootKey)
	auditRepo := storage.NewAuditRepo(db)
	recoveryCodeRepo := storage.NewRecoveryCodeRepo(db)
	oidcProvider := &oidcclient.Provider{}

	wizard := &setup.Wizard{
		Audit:                 auditRepo,
		SetupToken:            testSetupToken,
		Users:                 userRepo,
		AuthConfig:            authConfigRepo,
		RecoveryCodes:         recoveryCodeRepo,
		GenerateTOTP:          gototp.Generate,
		ValidateTOTP:          gototp.Validate,
		HashPassword:          crypto.HashPassword,
		GenerateRecoveryCodes: recoverycode.Generate,
		HashRecoveryCode:      crypto.HashToken,
	}
	loginService := &gosession.LoginService{
		Audit:          auditRepo,
		Users:          userRepo,
		Sessions:       sessionRepo,
		VerifyPassword: crypto.VerifyPassword,
		ValidateTOTP:   gototp.Validate,
	}

	handler := web.NewRouter(web.Deps{
		SetupChecker: authConfigRepo,
		SessionAuth:  sessionRepo,
		Setup:        web.NewSetupHandler(wizard, oidcProvider),
		Auth:         web.NewAuthHandler(loginService, sessionRepo, authConfigRepo, oidcProvider, userRepo, wizard, auditRepo),
		Recover: web.NewRecoverHandler(&recovery.Service{
			Users: userRepo, Resets: storage.NewResetRepo(db, rootKey), RecoveryCodes: recoveryCodeRepo, Sessions: sessionRepo,
			GenerateTOTP: gototp.Generate, ValidateTOTP: gototp.Validate, HashPassword: crypto.HashPassword, Audit: auditRepo,
		}),
		Secrets: web.NewSecretsHandler(secretRepo, auditRepo),
		Tokens:  web.NewTokensHandler(tokenRepo, secretRepo, auditRepo),
		Audit:   web.NewAuditHandler(auditRepo, tokenRepo),
	})

	return env{handler: handler, users: userRepo, sessions: sessionRepo, secrets: secretRepo, authConfig: authConfigRepo}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/readyz") //nolint:gosec // baseURL is test-local, not attacker-controlled
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("rqlited at %s did not become ready in time", baseURL)
}

func doForm(t *testing.T, handler http.Handler, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func extractSessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == gosession.CookieName {
			return c
		}
	}
	return nil
}

func TestWebRedirectsToSetupWhenIncomplete(t *testing.T) {
	e := newEnv(t)

	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("status=%d location=%q, want 303 to /setup", rec.Code, rec.Header().Get("Location"))
	}
}

func TestWebFullSetupLoginSecretFlow(t *testing.T) {
	e := newEnv(t)

	initRec := doForm(t, e.handler, "/setup", url.Values{
		"setup_token": {testSetupToken},
		"username":    {"admin"},
		"password":    {"correct horse battery staple"},
	}, nil)
	if initRec.Code != http.StatusOK {
		t.Fatalf("setup init status = %d, body=%s", initRec.Code, initRec.Body.String())
	}
	body := initRec.Body.String()
	secret := extractBetween(t, body, "<code>", "</code>")

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	confirmRec := doForm(t, e.handler, "/setup/confirm", url.Values{
		"setup_token": {testSetupToken},
		"username":    {"admin"},
		"code":        {code},
	}, nil)
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm status=%d, body=%s", confirmRec.Code, confirmRec.Body.String())
	}
	if !strings.Contains(confirmRec.Body.String(), "recovery codes") {
		t.Fatalf("expected the recovery-codes page, body=%s", confirmRec.Body.String())
	}

	loginRec := doForm(t, e.handler, "/login", url.Values{
		"username":  {"admin"},
		"password":  {"correct horse battery staple"},
		"totp_code": {code},
	}, nil)
	if loginRec.Code != http.StatusSeeOther || loginRec.Header().Get("Location") != "/secrets" {
		t.Fatalf("login status=%d location=%q, want 303 to /secrets; body=%s", loginRec.Code, loginRec.Header().Get("Location"), loginRec.Body.String())
	}
	sessionCookie := extractSessionCookie(loginRec)
	if sessionCookie == nil {
		t.Fatal("expected a session cookie to be set on login")
	}

	// Create a secret via the form.
	createRec := doForm(t, e.handler, "/secrets/new", url.Values{
		"name":  {"db-password"},
		"value": {"hunter2"},
	}, sessionCookie)
	if createRec.Code != http.StatusSeeOther {
		t.Fatalf("create secret status = %d, body=%s", createRec.Code, createRec.Body.String())
	}
	location := createRec.Header().Get("Location")
	if !strings.HasPrefix(location, "/secrets/") {
		t.Fatalf("expected redirect to /secrets/{id}, got %q", location)
	}

	// List shows it.
	listReq := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	listReq.AddCookie(sessionCookie)
	listRec := httptest.NewRecorder()
	e.handler.ServeHTTP(listRec, listReq)
	if !strings.Contains(listRec.Body.String(), "db-password") {
		t.Fatalf("expected secrets list to mention db-password, body=%s", listRec.Body.String())
	}

	// The detail page never contains the value; "show" fetches it.
	detailReq := httptest.NewRequest(http.MethodGet, location, nil)
	detailReq.AddCookie(sessionCookie)
	detailRec := httptest.NewRecorder()
	e.handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK || strings.Contains(detailRec.Body.String(), "hunter2") || !strings.Contains(detailRec.Body.String(), "data-reveal-url") {
		t.Fatalf("detail page status=%d, must not show the value: %s", detailRec.Code, detailRec.Body.String())
	}
	revealReq := httptest.NewRequest(http.MethodGet, location+"/value", nil)
	revealReq.AddCookie(sessionCookie)
	revealRec := httptest.NewRecorder()
	e.handler.ServeHTTP(revealRec, revealReq)
	if revealRec.Code != http.StatusOK || !strings.Contains(revealRec.Body.String(), `"value":"hunter2"`) {
		t.Fatalf("value status=%d, body=%s", revealRec.Code, revealRec.Body.String())
	}

	// Logout clears the cookie.
	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	logoutRec := httptest.NewRecorder()
	e.handler.ServeHTTP(logoutRec, logoutReq)
	cleared := extractSessionCookie(logoutRec)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("expected logout to clear the session cookie, got %+v", cleared)
	}

	// Secrets page now redirects to login.
	afterLogoutReq := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	afterLogoutReq.AddCookie(sessionCookie)
	afterLogoutRec := httptest.NewRecorder()
	e.handler.ServeHTTP(afterLogoutRec, afterLogoutReq)
	if afterLogoutRec.Code != http.StatusSeeOther || afterLogoutRec.Header().Get("Location") != "/login" {
		t.Fatalf("expected redirect to /login after a revoked session, got status=%d location=%q", afterLogoutRec.Code, afterLogoutRec.Header().Get("Location"))
	}
}

func TestWebLoginRejectsReplayedTOTPCode(t *testing.T) {
	e := newEnv(t)

	initRec := doForm(t, e.handler, "/setup", url.Values{
		"setup_token": {testSetupToken},
		"username":    {"admin"},
		"password":    {"correct horse battery staple"},
	}, nil)
	secret := extractBetween(t, initRec.Body.String(), "<code>", "</code>")

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	doForm(t, e.handler, "/setup/confirm", url.Values{
		"setup_token": {testSetupToken},
		"username":    {"admin"},
		"code":        {code},
	}, nil)

	firstLogin := doForm(t, e.handler, "/login", url.Values{
		"username":  {"admin"},
		"password":  {"correct horse battery staple"},
		"totp_code": {code},
	}, nil)
	if firstLogin.Code != http.StatusSeeOther {
		t.Fatalf("first login status = %d, body=%s", firstLogin.Code, firstLogin.Body.String())
	}

	// Replaying the exact same code must be rejected, even though it's
	// still within its normal TOTP validity window.
	secondLogin := doForm(t, e.handler, "/login", url.Values{
		"username":  {"admin"},
		"password":  {"correct horse battery staple"},
		"totp_code": {code},
	}, nil)
	if secondLogin.Code != http.StatusUnauthorized {
		t.Fatalf("replayed login status = %d, want %d; body=%s", secondLogin.Code, http.StatusUnauthorized, secondLogin.Body.String())
	}
}

func TestWebSecretsRequiresSession(t *testing.T) {
	e := newEnv(t)
	// Complete setup via storage directly to isolate this test from the
	// wizard flow (already covered above).
	completeSetupDirect(t, e)

	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secrets", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status=%d location=%q, want 303 to /login", rec.Code, rec.Header().Get("Location"))
	}
}

// completeSetupDirect creates the account and marks setup complete,
// bypassing the HTTP wizard for tests that don't care about it.
func completeSetupDirect(t *testing.T, e env) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.users.SetupPassword(ctx, "owner", "x"); err != nil {
		t.Fatalf("SetupPassword: %v", err)
	}
	if err := e.users.SetTOTPSecret(ctx, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}
	if err := e.authConfig.CompletePasswordTOTP(ctx); err != nil {
		t.Fatalf("CompletePasswordTOTP: %v", err)
	}
}

func extractBetween(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i == -1 {
		t.Fatalf("marker %q not found in %q", start, s)
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j == -1 {
		t.Fatalf("end marker %q not found in %q", end, rest)
	}
	return rest[:j]
}
