package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestBreakGlassCodeWorksOnceAndExpires(t *testing.T) {
	db, _ := newTestDB(t)
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
	db, _ := newTestDB(t)
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
	if done, err := repo.Finish(ctx, "reset-hash"); err != nil || !done {
		t.Fatalf("Finish: %v, %v", done, err)
	}
	if done, _ := repo.Finish(ctx, "reset-hash"); done {
		t.Fatal("finished twice")
	}
	if _, ok, _ := repo.Get(ctx, "reset-hash"); ok {
		t.Fatal("finished reset still pending")
	}
}
