package storage_test

import (
	"context"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func TestAuditRepoLog(t *testing.T) {
	db, baseURL := newTestDB(t)
	userID := insertTestUser(t, baseURL, "audit-user")
	repo := storage.NewAuditRepo(db)

	if err := repo.Log(context.Background(), "user", userID, "reveal", "secret", 1); err != nil {
		t.Fatalf("Log: %v", err)
	}
}
