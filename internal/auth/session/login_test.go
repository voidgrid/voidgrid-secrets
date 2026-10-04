package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

type fakeUserLookup struct {
	rec      model.UserAuthRecord
	err      error
	lastCode string
}

func (f *fakeUserLookup) GetAuthRecord(_ context.Context, _ string) (model.UserAuthRecord, error) {
	return f.rec, f.err
}

func (f *fakeUserLookup) ConsumeTOTPCode(_ context.Context, _ int64, code string) (bool, error) {
	if f.lastCode != "" && f.lastCode == code {
		return false, nil
	}
	f.lastCode = code
	return true, nil
}

type fakeSessionCreator struct {
	token     string
	expiresAt time.Time
	err       error
}

func (f fakeSessionCreator) Create(_ context.Context, _ int64, _ time.Duration) (string, time.Time, error) {
	return f.token, f.expiresAt, f.err
}

type fakeRecoveryCodeConsumer struct {
	validHash string
	used      bool
}

func (f *fakeRecoveryCodeConsumer) Consume(_ context.Context, _ int64, codeHash string) (bool, error) {
	if f.used || codeHash != f.validHash {
		return false, nil
	}
	f.used = true
	return true, nil
}

func validLoginService(rec model.UserAuthRecord) *session.LoginService {
	return &session.LoginService{
		Users:          &fakeUserLookup{rec: rec},
		Sessions:       fakeSessionCreator{token: "vgs_sess_abc", expiresAt: time.Now().Add(time.Hour)}, //nolint:gosec // fake test fixture, not a real credential
		VerifyPassword: func(password, hash string) (bool, error) { return password == hash, nil },
		ValidateTOTP:   func(code, secret string) bool { return code == secret },
	}
}

func TestLoginRejectsReplayedTOTPCode(t *testing.T) {
	svc := validLoginService(model.UserAuthRecord{
		User:         model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP},
		PasswordHash: "correct-password",
		TOTPSecret:   "123456",
	})

	if _, _, err := svc.Login(context.Background(), "alice", "correct-password", "123456"); err != nil {
		t.Fatalf("first login: %v", err)
	}

	_, _, err := svc.Login(context.Background(), "alice", "correct-password", "123456")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials (replayed TOTP code)", err)
	}
}

func TestLoginSucceeds(t *testing.T) {
	svc := validLoginService(model.UserAuthRecord{
		User:         model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP},
		PasswordHash: "correct-password",
		TOTPSecret:   "123456",
	})

	tok, _, err := svc.Login(context.Background(), "alice", "correct-password", "123456")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok != "vgs_sess_abc" {
		t.Fatalf("got token %q, want %q", tok, "vgs_sess_abc")
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	svc := validLoginService(model.UserAuthRecord{
		User:         model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP},
		PasswordHash: "correct-password",
		TOTPSecret:   "123456",
	})

	_, _, err := svc.Login(context.Background(), "alice", "wrong-password", "123456")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginRejectsWrongTOTPCode(t *testing.T) {
	svc := validLoginService(model.UserAuthRecord{
		User:         model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP},
		PasswordHash: "correct-password",
		TOTPSecret:   "123456",
	})

	_, _, err := svc.Login(context.Background(), "alice", "correct-password", "000000")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginRejectsMissingTOTPEnrollmentEvenWithCorrectPassword(t *testing.T) {
	svc := validLoginService(model.UserAuthRecord{
		User:         model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP},
		PasswordHash: "correct-password",
		TOTPSecret:   "", // not enrolled
	})

	_, _, err := svc.Login(context.Background(), "alice", "correct-password", "")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials (no TOTP bypass)", err)
	}
}

func TestLoginRejectsDisabledUser(t *testing.T) {
	svc := validLoginService(model.UserAuthRecord{
		User:         model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP, Disabled: true},
		PasswordHash: "correct-password",
		TOTPSecret:   "123456",
	})

	_, _, err := svc.Login(context.Background(), "alice", "correct-password", "123456")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginRejectsOIDCOnlyUser(t *testing.T) {
	svc := validLoginService(model.UserAuthRecord{
		User: model.User{ID: 1, AuthMethod: model.AuthOIDC},
	})

	_, _, err := svc.Login(context.Background(), "alice", "anything", "123456")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginRejectsUnknownUser(t *testing.T) {
	svc := &session.LoginService{
		Users:          &fakeUserLookup{err: errors.New("not found")},
		Sessions:       fakeSessionCreator{},
		VerifyPassword: func(_, _ string) (bool, error) { return true, nil },
		ValidateTOTP:   func(_, _ string) bool { return true },
	}

	_, _, err := svc.Login(context.Background(), "nobody", "x", "123456")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWithRecoveryCodeSucceedsRegardlessOfAuthMethod(t *testing.T) {
	for _, method := range []model.AuthMethod{model.AuthPasswordTOTP, model.AuthOIDC} {
		svc := &session.LoginService{
			Users:         &fakeUserLookup{rec: model.UserAuthRecord{User: model.User{ID: 1, AuthMethod: method}}},
			Sessions:      fakeSessionCreator{token: "vgs_sess_abc", expiresAt: time.Now().Add(time.Hour)}, //nolint:gosec // fake test fixture, not a real credential
			RecoveryCodes: &fakeRecoveryCodeConsumer{validHash: crypto.HashToken("ABCDE-FGHIJ")},
		}

		tok, _, err := svc.LoginWithRecoveryCode(context.Background(), "alice", "ABCDE-FGHIJ")
		if err != nil {
			t.Fatalf("auth method %q: LoginWithRecoveryCode: %v", method, err)
		}
		if tok != "vgs_sess_abc" {
			t.Fatalf("auth method %q: got token %q, want %q", method, tok, "vgs_sess_abc")
		}
	}
}

func TestLoginWithRecoveryCodeIsSingleUse(t *testing.T) {
	svc := &session.LoginService{
		Users:         &fakeUserLookup{rec: model.UserAuthRecord{User: model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP}}},
		Sessions:      fakeSessionCreator{token: "vgs_sess_abc", expiresAt: time.Now().Add(time.Hour)}, //nolint:gosec // fake test fixture, not a real credential
		RecoveryCodes: &fakeRecoveryCodeConsumer{validHash: crypto.HashToken("ABCDE-FGHIJ")},
	}

	if _, _, err := svc.LoginWithRecoveryCode(context.Background(), "alice", "ABCDE-FGHIJ"); err != nil {
		t.Fatalf("first use: %v", err)
	}

	_, _, err := svc.LoginWithRecoveryCode(context.Background(), "alice", "ABCDE-FGHIJ")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials (code already used)", err)
	}
}

func TestLoginWithRecoveryCodeRejectsWrongCode(t *testing.T) {
	svc := &session.LoginService{
		Users:         &fakeUserLookup{rec: model.UserAuthRecord{User: model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP}}},
		Sessions:      fakeSessionCreator{token: "vgs_sess_abc", expiresAt: time.Now().Add(time.Hour)}, //nolint:gosec // fake test fixture, not a real credential
		RecoveryCodes: &fakeRecoveryCodeConsumer{validHash: crypto.HashToken("ABCDE-FGHIJ")},
	}

	_, _, err := svc.LoginWithRecoveryCode(context.Background(), "alice", "WRONG-CODE")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWithRecoveryCodeRejectsDisabledUser(t *testing.T) {
	svc := &session.LoginService{
		Users:         &fakeUserLookup{rec: model.UserAuthRecord{User: model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP, Disabled: true}}},
		Sessions:      fakeSessionCreator{token: "vgs_sess_abc", expiresAt: time.Now().Add(time.Hour)}, //nolint:gosec // fake test fixture, not a real credential
		RecoveryCodes: &fakeRecoveryCodeConsumer{validHash: crypto.HashToken("ABCDE-FGHIJ")},
	}

	_, _, err := svc.LoginWithRecoveryCode(context.Background(), "alice", "ABCDE-FGHIJ")
	if !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("got err = %v, want ErrInvalidCredentials", err)
	}
}
