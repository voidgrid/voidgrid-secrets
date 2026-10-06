package setup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
)

// fakeUserStore holds at most one account, like the real one.
type fakeUserStore struct {
	account *model.UserAuthRecord
}

func (f *fakeUserStore) SetupPassword(_ context.Context, username, passwordHash string) (model.User, error) {
	f.account = &model.UserAuthRecord{User: model.User{ID: 1, Username: username, AuthMethod: model.AuthPasswordTOTP}, PasswordHash: passwordHash}
	return f.account.User, nil
}

func (f *fakeUserStore) SetupOIDC(_ context.Context, username, subject string) (model.User, error) {
	if username == "" {
		username = subject
	}
	f.account = &model.UserAuthRecord{User: model.User{ID: 1, Username: username, AuthMethod: model.AuthOIDC}, OIDCSubject: subject}
	return f.account.User, nil
}

func (f *fakeUserStore) SetTOTPSecret(_ context.Context, secret string) error {
	if f.account == nil {
		return errors.New("no account")
	}
	f.account.TOTPSecret = secret
	return nil
}

func (f *fakeUserStore) GetAuthRecord(_ context.Context, username string) (model.UserAuthRecord, error) {
	if f.account == nil || f.account.Username != username {
		return model.UserAuthRecord{}, errors.New("not found")
	}
	return *f.account, nil
}

type fakeAuthConfigStore struct {
	complete bool
	method   model.AuthMethod
}

func (f *fakeAuthConfigStore) IsComplete(_ context.Context) (bool, error) { return f.complete, nil }

func (f *fakeAuthConfigStore) CompletePasswordTOTP(_ context.Context) error {
	f.complete, f.method = true, model.AuthPasswordTOTP
	return nil
}

func (f *fakeAuthConfigStore) SaveOIDC(_ context.Context, _, _, _, _ string) error {
	f.method = model.AuthOIDC
	return nil
}

func (f *fakeAuthConfigStore) CompleteOIDC(_ context.Context) error {
	if f.method != model.AuthOIDC {
		return errors.New("no pending OIDC config")
	}
	f.complete = true
	return nil
}

func (f *fakeAuthConfigStore) Get(_ context.Context) (model.AuthConfig, error) {
	if f.method == "" {
		return model.AuthConfig{}, errors.New("none")
	}
	return model.AuthConfig{AuthMethod: f.method, OIDCIssuer: "https://issuer.example"}, nil
}

type fakeRecoveryCodeStore struct {
	codesByUser map[int64][]string
}

func (f *fakeRecoveryCodeStore) ReplaceForUser(_ context.Context, userID int64, hashedCodes []string) error {
	if f.codesByUser == nil {
		f.codesByUser = map[int64][]string{}
	}
	f.codesByUser[userID] = hashedCodes
	return nil
}

const testSetupToken = "vgs_setup_test" //nolint:gosec // fake test fixture, not a real credential

type fixture struct {
	w      *setup.Wizard
	users  *fakeUserStore
	config *fakeAuthConfigStore
	codes  *fakeRecoveryCodeStore
}

func newTestWizard() fixture {
	f := fixture{users: &fakeUserStore{}, config: &fakeAuthConfigStore{}, codes: &fakeRecoveryCodeStore{}}
	f.w = &setup.Wizard{
		SetupToken:    testSetupToken,
		Users:         f.users,
		AuthConfig:    f.config,
		RecoveryCodes: f.codes,
		GenerateTOTP: func(account string) (string, string, error) {
			return "totp-secret-for-" + account, "otpauth://totp/x", nil
		},
		ValidateTOTP: func(code, _ string) bool { return code == "valid-code" },
		HashPassword: func(password string) (string, error) { return "hashed:" + password, nil },
		GenerateRecoveryCodes: func() ([]string, error) {
			return []string{"code-1", "code-2"}, nil
		},
		HashRecoveryCode: func(code string) string { return "hashed:" + code },
	}
	return f
}

const callback = "https://app.example/login/oidc/callback"

func TestPasswordSetupCompletesAfterConfirm(t *testing.T) {
	f := newTestWizard()
	ctx := context.Background()

	secret, uri, err := f.w.InitPasswordSetup(ctx, testSetupToken, "owner", "hunter2")
	if err != nil || secret == "" || uri == "" {
		t.Fatalf("InitPasswordSetup = %q, %q, %v", secret, uri, err)
	}
	if f.config.complete {
		t.Fatal("setup complete before TOTP was confirmed")
	}
	codes, err := f.w.ConfirmPasswordSetup(ctx, testSetupToken, "owner", "valid-code")
	if err != nil || len(codes) == 0 {
		t.Fatalf("ConfirmPasswordSetup = %v, %v", codes, err)
	}
	if !f.config.complete || len(f.codes.codesByUser[1]) != 2 {
		t.Fatal("setup not completed, or recovery codes not stored")
	}
}

func TestPasswordSetupRejectsWrongCode(t *testing.T) {
	f := newTestWizard()
	ctx := context.Background()
	if _, _, err := f.w.InitPasswordSetup(ctx, testSetupToken, "owner", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.w.ConfirmPasswordSetup(ctx, testSetupToken, "owner", "wrong-code"); !errors.Is(err, setup.ErrInvalidCode) {
		t.Fatalf("err = %v, want ErrInvalidCode", err)
	}
}

// An unfinished password setup (lost QR code) can simply be started again.
func TestPasswordSetupCanRestartBeforeConfirming(t *testing.T) {
	f := newTestWizard()
	ctx := context.Background()
	if _, _, err := f.w.InitPasswordSetup(ctx, testSetupToken, "first", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.w.InitPasswordSetup(ctx, testSetupToken, "second", "hunter3"); err != nil {
		t.Fatalf("restarting setup: %v", err)
	}
	if f.users.account.Username != "second" {
		t.Fatalf("account = %q, want the restarted one", f.users.account.Username)
	}
}

func TestConfirmBeforeInitIsRefused(t *testing.T) {
	f := newTestWizard()
	if _, err := f.w.ConfirmPasswordSetup(context.Background(), testSetupToken, "owner", "valid-code"); !errors.Is(err, setup.ErrNotStarted) {
		t.Fatalf("err = %v, want ErrNotStarted", err)
	}
}

func TestOIDCSetupCompletesOnlyWhenClaimed(t *testing.T) {
	f := newTestWizard()
	ctx := context.Background()

	if err := f.w.SetupOIDC(ctx, testSetupToken, "https://issuer.example", "id", "secret", callback); err != nil {
		t.Fatalf("SetupOIDC: %v", err)
	}
	if f.config.complete {
		t.Fatal("OIDC setup completed before anyone signed in")
	}
	user, codes, err := f.w.ClaimOIDC(ctx, testSetupToken, "subject-1", "owner")
	if err != nil {
		t.Fatalf("ClaimOIDC: %v", err)
	}
	if user.Username != "owner" || f.users.account.OIDCSubject != "subject-1" || len(codes) == 0 || !f.config.complete {
		t.Fatalf("claim result: user %+v, codes %v, complete %v", user, codes, f.config.complete)
	}
	// Once claimed, setup is over: nobody else can claim.
	if _, _, err := f.w.ClaimOIDC(ctx, testSetupToken, "subject-2", "intruder"); !errors.Is(err, setup.ErrAlreadyComplete) {
		t.Fatalf("second claim: err = %v, want ErrAlreadyComplete", err)
	}
}

func TestClaimBeforeOIDCConfigIsRefused(t *testing.T) {
	f := newTestWizard()
	if _, _, err := f.w.ClaimOIDC(context.Background(), testSetupToken, "subject-1", "owner"); !errors.Is(err, setup.ErrNotStarted) {
		t.Fatalf("err = %v, want ErrNotStarted", err)
	}
}

func TestSetupStepsRefusedOnceComplete(t *testing.T) {
	f := newTestWizard()
	f.config.complete = true
	ctx := context.Background()
	if _, _, err := f.w.InitPasswordSetup(ctx, testSetupToken, "owner", "hunter2"); !errors.Is(err, setup.ErrAlreadyComplete) {
		t.Fatalf("InitPasswordSetup: %v", err)
	}
	if err := f.w.SetupOIDC(ctx, testSetupToken, "https://issuer.example", "id", "secret", callback); !errors.Is(err, setup.ErrAlreadyComplete) {
		t.Fatalf("SetupOIDC: %v", err)
	}
}

func TestEverySetupStepRequiresTheSetupToken(t *testing.T) {
	f := newTestWizard()
	ctx := context.Background()

	if _, _, err := f.w.InitPasswordSetup(ctx, "wrong", "owner", "hunter2"); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("InitPasswordSetup: %v", err)
	}
	if _, err := f.w.ConfirmPasswordSetup(ctx, "", "owner", "valid-code"); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("ConfirmPasswordSetup: %v", err)
	}
	if err := f.w.SetupOIDC(ctx, "wrong", "https://issuer.example", "id", "secret", callback); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("SetupOIDC: %v", err)
	}
	if _, _, err := f.w.ClaimOIDC(ctx, "wrong", "subject-1", "owner"); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("ClaimOIDC: %v", err)
	}
	if f.config.complete || f.users.account != nil {
		t.Fatal("something was set up without the token")
	}
}

func TestSetupRefusedWhenNoTokenConfigured(t *testing.T) {
	f := newTestWizard()
	f.w.SetupToken = ""
	if err := f.w.CheckSetupToken(context.Background(), ""); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("empty configured token accepted an empty token: %v", err)
	}
}
