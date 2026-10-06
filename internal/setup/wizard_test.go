package setup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
)

type fakeUserStore struct {
	users       map[string]model.UserAuthRecord
	nextID      int64
	totpSecrets map[int64]string
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{users: map[string]model.UserAuthRecord{}, totpSecrets: map[int64]string{}}
}

func (f *fakeUserStore) CreateWithPassword(_ context.Context, username, passwordHash string) (model.User, error) {
	if _, exists := f.users[username]; exists {
		return model.User{}, errors.New("already exists")
	}
	f.nextID++
	u := model.User{ID: f.nextID, Username: username, AuthMethod: model.AuthPasswordTOTP}
	f.users[username] = model.UserAuthRecord{User: u, PasswordHash: passwordHash}
	return u, nil
}

func (f *fakeUserStore) SetTOTPSecret(_ context.Context, userID int64, secret string) error {
	f.totpSecrets[userID] = secret
	for username, rec := range f.users {
		if rec.ID == userID {
			rec.TOTPSecret = secret
			f.users[username] = rec
		}
	}
	return nil
}

func (f *fakeUserStore) GetAuthRecord(_ context.Context, username string) (model.UserAuthRecord, error) {
	rec, ok := f.users[username]
	if !ok {
		return model.UserAuthRecord{}, errors.New("not found")
	}
	return rec, nil
}

func (f *fakeUserStore) CountUsers(_ context.Context) (int64, error) {
	return int64(len(f.users)), nil
}

func (f *fakeUserStore) PromoteToAdmin(_ context.Context, userID int64) error {
	for username, rec := range f.users {
		if rec.ID == userID {
			rec.IsAdmin = true
			f.users[username] = rec
		}
	}
	return nil
}

type fakeAuthConfigStore struct {
	complete bool
}

func (f *fakeAuthConfigStore) IsComplete(_ context.Context) (bool, error) {
	return f.complete, nil
}

func (f *fakeAuthConfigStore) CompletePasswordTOTP(_ context.Context) error {
	f.complete = true
	return nil
}

func (f *fakeAuthConfigStore) CompleteOIDC(_ context.Context, _, _, _, _ string) error {
	f.complete = true
	return nil
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

func newTestWizard() (*setup.Wizard, *fakeAuthConfigStore) {
	users := newFakeUserStore()
	authConfig := &fakeAuthConfigStore{}
	w := &setup.Wizard{
		SetupToken:    testSetupToken,
		Users:         users,
		AuthConfig:    authConfig,
		RecoveryCodes: &fakeRecoveryCodeStore{},
		GenerateTOTP: func(account string) (string, string, error) {
			return "totp-secret-for-" + account, "otpauth://totp/x", nil
		},
		ValidateTOTP: func(code, secret string) bool { return code == "valid-code" },
		HashPassword: func(password string) (string, error) { return "hashed:" + password, nil },
		GenerateRecoveryCodes: func() ([]string, error) {
			return []string{"code-1", "code-2"}, nil
		},
		HashRecoveryCode: func(code string) string { return "hashed:" + code },
	}
	return w, authConfig
}

func TestInitAndConfirmPasswordSetupCompletesWizard(t *testing.T) {
	w, authConfig := newTestWizard()
	ctx := context.Background()

	secret, uri, err := w.InitPasswordSetup(ctx, testSetupToken, "admin", "hunter2")
	if err != nil {
		t.Fatalf("InitPasswordSetup: %v", err)
	}
	if secret == "" || uri == "" {
		t.Fatal("expected a non-empty secret and provisioning URI")
	}

	complete, err := w.IsComplete(ctx)
	if err != nil {
		t.Fatalf("IsComplete: %v", err)
	}
	if complete {
		t.Fatal("expected setup to still be incomplete before confirmation")
	}

	codes, err := w.ConfirmPasswordSetup(ctx, testSetupToken, "admin", "valid-code")
	if err != nil {
		t.Fatalf("ConfirmPasswordSetup: %v", err)
	}
	if len(codes) == 0 {
		t.Fatal("expected a non-empty batch of recovery codes")
	}
	if !authConfig.complete {
		t.Fatal("expected setup to be marked complete")
	}
}

func TestConfirmPasswordSetupRejectsInvalidCode(t *testing.T) {
	w, _ := newTestWizard()
	ctx := context.Background()

	if _, _, err := w.InitPasswordSetup(ctx, testSetupToken, "admin", "hunter2"); err != nil {
		t.Fatalf("InitPasswordSetup: %v", err)
	}

	_, err := w.ConfirmPasswordSetup(ctx, testSetupToken, "admin", "wrong-code")
	if !errors.Is(err, setup.ErrInvalidCode) {
		t.Fatalf("got err = %v, want ErrInvalidCode", err)
	}
}

func TestInitPasswordSetupRejectsSecondAdmin(t *testing.T) {
	w, _ := newTestWizard()
	ctx := context.Background()

	if _, _, err := w.InitPasswordSetup(ctx, testSetupToken, "admin", "hunter2"); err != nil {
		t.Fatalf("InitPasswordSetup: %v", err)
	}

	_, _, err := w.InitPasswordSetup(ctx, testSetupToken, "admin2", "hunter3")
	if !errors.Is(err, setup.ErrAdminPending) {
		t.Fatalf("got err = %v, want ErrAdminPending", err)
	}
}

func TestInitPasswordSetupRejectsWhenAlreadyComplete(t *testing.T) {
	w, authConfig := newTestWizard()
	authConfig.complete = true

	_, _, err := w.InitPasswordSetup(context.Background(), testSetupToken, "admin", "hunter2")
	if !errors.Is(err, setup.ErrAlreadyComplete) {
		t.Fatalf("got err = %v, want ErrAlreadyComplete", err)
	}
}

func TestSetupOIDCRejectsWhenAlreadyComplete(t *testing.T) {
	w, authConfig := newTestWizard()
	authConfig.complete = true

	err := w.SetupOIDC(context.Background(), testSetupToken, "https://issuer.example", "client-id", "client-secret", "https://app.example/login/oidc/callback")
	if !errors.Is(err, setup.ErrAlreadyComplete) {
		t.Fatalf("got err = %v, want ErrAlreadyComplete", err)
	}
}

func TestSetupOIDCSucceeds(t *testing.T) {
	w, authConfig := newTestWizard()

	if err := w.SetupOIDC(context.Background(), testSetupToken, "https://issuer.example", "client-id", "client-secret", "https://app.example/login/oidc/callback"); err != nil {
		t.Fatalf("SetupOIDC: %v", err)
	}
	if !authConfig.complete {
		t.Fatal("expected setup to be marked complete")
	}
}

func TestEverySetupStepRequiresTheSetupToken(t *testing.T) {
	w, authConfig := newTestWizard()
	ctx := context.Background()

	if _, _, err := w.InitPasswordSetup(ctx, "wrong", "admin", "hunter2"); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("InitPasswordSetup with wrong token: err = %v", err)
	}
	if _, _, err := w.InitPasswordSetup(ctx, testSetupToken, "admin", "hunter2"); err != nil {
		t.Fatalf("InitPasswordSetup: %v", err)
	}
	if _, err := w.ConfirmPasswordSetup(ctx, "", "admin", "valid-code"); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("ConfirmPasswordSetup with no token: err = %v", err)
	}
	if err := w.SetupOIDC(ctx, "wrong", "https://issuer.example", "id", "secret", "https://app.example/cb"); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("SetupOIDC with wrong token: err = %v", err)
	}
	if authConfig.complete {
		t.Fatal("setup completed without the token")
	}
}

func TestSetupRefusedWhenNoTokenConfigured(t *testing.T) {
	w, _ := newTestWizard()
	w.SetupToken = ""
	if err := w.CheckSetupToken(context.Background(), ""); !errors.Is(err, setup.ErrInvalidSetupToken) {
		t.Fatalf("empty configured token accepted an empty token: %v", err)
	}
}
