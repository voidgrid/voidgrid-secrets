package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestBreakGlassCodeWorksOnceAndExpires(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewResetRepo(db, make([]byte, crypto.KeySize))
	soon := time.Now().Add(time.Minute)

	if err := repo.IssueBreakGlass(ctx, "code-hash", soon); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.RedeemBreakGlass(ctx, "wrong-hash", "reset-1", soon); err != nil || ok {
		t.Fatalf("wrong code redeemed: %v, %v", ok, err)
	}
	if ok, err := repo.RedeemBreakGlass(ctx, "code-hash", "reset-1", soon); err != nil || !ok {
		t.Fatalf("redeem: %v, %v", ok, err)
	}
	if ok, _ := repo.RedeemBreakGlass(ctx, "code-hash", "reset-2", soon); ok {
		t.Fatal("break-glass code redeemed twice")
	}

	if err := repo.IssueBreakGlass(ctx, "old-hash", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.RedeemBreakGlass(ctx, "old-hash", "reset-3", soon); ok {
		t.Fatal("expired break-glass code redeemed")
	}
}

func TestResetCarriesPendingTOTPAndFinishesOnce(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewResetRepo(db, make([]byte, crypto.KeySize))

	if err := repo.Start(ctx, "reset-hash", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetPendingTOTP(ctx, "reset-hash", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	reset, ok, err := repo.Get(ctx, "reset-hash")
	if err != nil || !ok || reset.Source != storage.ResetFromRecoveryCode || reset.PendingTOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Get = %+v, %v, %v", reset, ok, err)
	}
	rootKey := make([]byte, crypto.KeySize)
	users := storage.NewUserRepo(db, rootKey)
	u, err := users.SetupPassword(ctx, "owner", "old-hash")
	if err != nil {
		t.Fatal(err)
	}
	codes := storage.NewRecoveryCodeRepo(db)
	sessions := storage.NewSessionRepo(db)
	oldSession, _, err := sessions.Create(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if done, err := repo.Complete(ctx, "reset-hash", u.ID, "new-hash", "JBSWY3DPEHPK3PXP", []string{"code-1", "code-2"}); err != nil || !done {
		t.Fatalf("Complete: %v, %v", done, err)
	}
	rec, err := users.AuthRecord(ctx)
	if err != nil || rec.PasswordHash != "new-hash" || rec.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("after Complete: %+v, %v", rec, err)
	}
	if n, _ := codes.CountUnused(ctx, u.ID); n != 2 {
		t.Fatalf("recovery codes = %d, want 2", n)
	}
	if _, err := sessions.Authenticate(ctx, oldSession); err == nil {
		t.Fatal("old session survived the reset")
	}

	// A spent reset changes nothing at all.
	if done, _ := repo.Complete(ctx, "reset-hash", u.ID, "other-hash", "JBSWY3DPEHPK3PXP", []string{"code-3"}); done {
		t.Fatal("completed twice")
	}
	if rec, _ := users.AuthRecord(ctx); rec.PasswordHash != "new-hash" {
		t.Fatalf("spent reset changed the password to %q", rec.PasswordHash)
	}
	if n, _ := codes.CountUnused(ctx, u.ID); n != 2 {
		t.Fatalf("spent reset changed the recovery codes: %d", n)
	}
	if _, ok, _ := repo.Get(ctx, "reset-hash"); ok {
		t.Fatal("finished reset still pending")
	}
}
