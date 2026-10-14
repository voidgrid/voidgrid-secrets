package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/voidgrid/voidgrid-secrets/internal/audit"
	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
	"github.com/voidgrid/voidgrid-secrets/internal/web"
)

const (
	accountPassword = "correct horse battery staple"
	accountTOTP     = "JBSWY3DPEHPK3PXP"
)

// passwordAccount makes a real password+TOTP account (completeSetupDirect
// stores an unverifiable password hash) and returns its session.
func passwordAccount(t *testing.T, e env) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	hash, err := crypto.HashPassword(accountPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.users.SetupPassword(ctx, "owner", hash); err != nil {
		t.Fatal(err)
	}
	if err := e.users.SetTOTPSecret(ctx, accountTOTP); err != nil {
		t.Fatal(err)
	}
	if err := e.authConfig.CompletePasswordTOTP(ctx); err != nil {
		t.Fatal(err)
	}
	return ownerSession(t, e)
}

// totpAt gives a code from the current 30-second window or the next one.
// The replay guard refuses a code equal to the last one used, so tests
// alternate between the two; either is accepted (one period of skew).
func totpAt(t *testing.T, next bool) string {
	t.Helper()
	at := time.Now()
	if next {
		at = at.Add(30 * time.Second)
	}
	code, err := totp.GenerateCode(accountTOTP, at)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func auditCount(t *testing.T, e env, action string) int {
	t.Helper()
	entries, err := e.audit.List(context.Background(), storage.AuditFilter{Action: action, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestAccountRegeneratesRecoveryCodesAfterReauth(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cookie := passwordAccount(t, e)
	codes := storage.NewRecoveryCodeRepo(e.db)
	if err := codes.ReplaceForUser(ctx, 1, []string{crypto.HashToken("old-one"), crypto.HashToken("old-two"), crypto.HashToken("old-three")}); err != nil {
		t.Fatal(err)
	}

	if rec := get(t, e, "/account", nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("signed out: %d %q, want redirect to /login", rec.Code, rec.Header().Get("Location"))
	}
	page := get(t, e, "/account", cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "3 unused") {
		t.Fatalf("account page: %d %s", page.Code, page.Body.String())
	}

	for name, form := range map[string]url.Values{
		"wrong password": {"password": {"nope nope nope nope"}, "totp_code": {totpAt(t, false)}},
		"wrong code":     {"password": {accountPassword}, "totp_code": {"000000"}},
		"empty":          {},
	} {
		rec := doForm(t, e.handler, "/account/recovery-codes", form, cookie)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
		if n, _ := codes.CountUnused(ctx, 1); n != 3 {
			t.Fatalf("%s: unused codes = %d, want the old 3 untouched", name, n)
		}
	}
	if n := auditCount(t, e, audit.ReauthFailed); n != 3 {
		t.Errorf("reauth_failed entries = %d, want 3", n)
	}
	if rec := doForm(t, e.handler, "/account/recovery-codes", url.Values{"password": {accountPassword}, "totp_code": {totpAt(t, false)}}, nil); rec.Code != http.StatusSeeOther {
		t.Errorf("signed out POST: %d, want redirect to /login", rec.Code)
	}

	rec := doForm(t, e.handler, "/account/recovery-codes", url.Values{"password": {accountPassword}, "totp_code": {totpAt(t, true)}}, cookie)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "recovery codes") {
		t.Fatalf("regenerate: %d %s", rec.Code, rec.Body.String())
	}
	if n, _ := codes.CountUnused(ctx, 1); n != 10 {
		t.Fatalf("unused after regenerate = %d, want 10", n)
	}
	for _, old := range []string{"old-one", "old-two", "old-three"} {
		if ok, _ := codes.Consume(ctx, 1, crypto.HashToken(old)); ok {
			t.Errorf("old code %q still works", old)
		}
	}
	shown := strings.Fields(extractBetween(t, rec.Body.String(), `<pre class="recovery-codes">`, "</pre>"))
	if len(shown) != 10 {
		t.Fatalf("codes shown = %d, want 10", len(shown))
	}
	if ok, err := codes.Consume(ctx, 1, crypto.HashToken(shown[0])); err != nil || !ok {
		t.Errorf("a shown code does not work: ok=%v err=%v", ok, err)
	}
	if n := auditCount(t, e, audit.RecoveryCodesRegenerated); n != 1 {
		t.Errorf("recovery_codes_regenerated entries = %d, want 1", n)
	}
}

type fakeOwner struct{ subject string }

func (f fakeOwner) OIDCOwner(_ context.Context, subject string) (model.User, error) {
	if subject != f.subject {
		return model.User{}, storage.ErrNotOwner
	}
	return model.User{ID: 1, Username: "owner", AuthMethod: model.AuthOIDC}, nil
}

type fakeIssuer struct{ regenerated []string }

func (f *fakeIssuer) RegenerateCodes(_ context.Context, _ int64, method string) ([]string, error) {
	f.regenerated = append(f.regenerated, method)
	return []string{"AAAA-BBBB"}, nil
}

func (f *fakeIssuer) UnusedCodes(context.Context, int64) (int, error) { return 0, nil }

func TestOIDCReauthIssuesCodesOnlyForTheOwnerWithAFreshSignIn(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name string
		id   oidcclient.Identity
		want int
	}{
		{"owner, just signed in", oidcclient.Identity{Subject: "sub-1", AuthTime: time.Now().Add(-5 * time.Second)}, 200},
		{"owner, signed in an hour ago", oidcclient.Identity{Subject: "sub-1", AuthTime: time.Now().Add(-time.Hour)}, 403},
		{"owner, auth_time in the future", oidcclient.Identity{Subject: "sub-1", AuthTime: time.Now().Add(time.Hour)}, 403},
		{"owner, provider sent no auth_time", oidcclient.Identity{Subject: "sub-1"}, 403},
		{"someone else, just signed in", oidcclient.Identity{Subject: "sub-2", AuthTime: time.Now()}, 403},
	}
	for _, c := range cases {
		issuer := &fakeIssuer{}
		h := web.NewAccountHandler(nil, issuer, fakeOwner{subject: "sub-1"}, &oidcclient.Provider{}, e.audit)
		rec := httptest.NewRecorder()
		h.FinishOIDCReauth(rec, httptest.NewRequest(http.MethodGet, "/login/oidc/callback", nil), c.id)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d; body=%s", c.name, rec.Code, c.want, rec.Body.String())
		}
		if (c.want == 200) != (len(issuer.regenerated) == 1) {
			t.Errorf("%s: codes regenerated %v", c.name, issuer.regenerated)
		}
		if c.want == 200 && !strings.Contains(rec.Body.String(), "AAAA-BBBB") {
			t.Errorf("%s: codes not shown: %s", c.name, rec.Body.String())
		}
	}
	if n := auditCount(t, e, audit.ReauthFailed); n != 4 {
		t.Errorf("reauth_failed entries = %d, want 4", n)
	}
	if n := auditCount(t, e, audit.Reauth); n != 1 {
		t.Errorf("reauth entries = %d, want 1", n)
	}
}

func TestOIDCReauthStateIsMarked(t *testing.T) {
	if !oidcclient.IsReauthState(oidcclient.ReauthStatePrefix+oidcclient.State()) || oidcclient.IsReauthState(oidcclient.State()) {
		t.Fatal("IsReauthState does not tell a re-authentication state from a sign-in state")
	}
}
