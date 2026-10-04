package storage_test

import (
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestUserRepoConsumeTOTPCodeRejectsReplay(t *testing.T) {
	db, baseURL := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewUserRepo(db, make([]byte, crypto.KeySize))
	userID := insertTestUser(t, baseURL, "totp-replay-user")

	ok, err := repo.ConsumeTOTPCode(ctx, userID, "123456")
	if err != nil {
		t.Fatalf("ConsumeTOTPCode (first use): %v", err)
	}
	if !ok {
		t.Fatal("expected the first use of a code to succeed")
	}

	ok, err = repo.ConsumeTOTPCode(ctx, userID, "123456")
	if err != nil {
		t.Fatalf("ConsumeTOTPCode (replay): %v", err)
	}
	if ok {
		t.Fatal("expected reusing the same code to be rejected as a replay")
	}

	ok, err = repo.ConsumeTOTPCode(ctx, userID, "654321")
	if err != nil {
		t.Fatalf("ConsumeTOTPCode (next code): %v", err)
	}
	if !ok {
		t.Fatal("expected a different code to be accepted")
	}

	// The previously-replayed code is still rejected, but the first code
	// ("123456") is no longer the one on record, so this isn't testing
	// anything beyond "current last code is 654321" - re-using 654321 next
	// should now be the replay.
	ok, err = repo.ConsumeTOTPCode(ctx, userID, "654321")
	if err != nil {
		t.Fatalf("ConsumeTOTPCode (replay of second code): %v", err)
	}
	if ok {
		t.Fatal("expected reusing the second code to be rejected as a replay")
	}
}
