package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
)

func TestAttemptLimiterLocksOutThenExpires(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	l := session.NewAttemptLimiter(3, 15*time.Minute)
	l.Now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.Allow("alice") {
			t.Fatalf("attempt %d refused before the limit", i+1)
		}
		l.Fail("alice")
	}
	if l.Allow("alice") {
		t.Fatal("4th attempt allowed after 3 failures")
	}
	if !l.Allow("bob") {
		t.Fatal("another username was locked out too")
	}

	now = now.Add(15 * time.Minute)
	if !l.Allow("alice") {
		t.Fatal("still locked out after the window passed")
	}
}

func TestAttemptLimiterSuccessClearsFailures(t *testing.T) {
	l := session.NewAttemptLimiter(2, time.Hour)
	l.Fail("alice")
	l.Succeed("alice")
	l.Fail("alice")
	if !l.Allow("alice") {
		t.Fatal("a success should have reset the count")
	}
}

func TestNilAttemptLimiterAllowsEverything(t *testing.T) {
	var l *session.AttemptLimiter
	l.Fail("alice")
	l.Succeed("alice")
	if !l.Allow("alice") {
		t.Fatal("nil limiter refused an attempt")
	}
}

func TestLoginLockoutSkipsPasswordCheck(t *testing.T) {
	verifies := 0
	svc := validLoginService(model.UserAuthRecord{
		User:         model.User{ID: 1, AuthMethod: model.AuthPasswordTOTP},
		PasswordHash: "correct-password",
		TOTPSecret:   "123456",
	})
	svc.VerifyPassword = func(password, hash string) (bool, error) {
		verifies++
		return password == hash, nil
	}
	svc.Limiter = session.NewAttemptLimiter(2, time.Hour)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, _, err := svc.Login(ctx, "alice", "wrong", "123456"); !errors.Is(err, session.ErrInvalidCredentials) {
			t.Fatalf("failure %d: err = %v", i+1, err)
		}
	}
	// Locked out: even the right password is refused, without hashing.
	if _, _, err := svc.Login(ctx, "alice", "correct-password", "123456"); !errors.Is(err, session.ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts", err)
	}
	if verifies != 2 {
		t.Fatalf("password verified %d times, want 2 (none while locked out)", verifies)
	}
}

func TestLoginVerifiesPasswordEvenForUnknownUsers(t *testing.T) {
	var hashes []string
	svc := validLoginService(model.UserAuthRecord{})
	svc.Users = &fakeUserLookup{err: errors.New("user not found")}
	svc.VerifyPassword = func(_, hash string) (bool, error) {
		hashes = append(hashes, hash)
		return true, nil // even a "match" must not log in an unknown user
	}

	if _, _, err := svc.Login(context.Background(), "nobody", "pw", "123456"); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if len(hashes) != 1 || hashes[0] == "" {
		t.Fatalf("expected one verification against a dummy hash, got %q", hashes)
	}
}
