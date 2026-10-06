package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	authtoken "github.com/voidgrid/voidgrid-secrets/internal/auth/token"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

func rawExec(t *testing.T, baseURL, query string, args ...interface{}) {
	t.Helper()
	conn, err := gorqlite.Open(baseURL)
	if err != nil {
		t.Fatalf("open raw connection: %v", err)
	}
	defer conn.Close()
	res, err := conn.WriteParameterizedContext(context.Background(), []gorqlite.ParameterizedStatement{{Query: query, Arguments: args}})
	if err != nil || res[0].Err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func createTestSecret(t *testing.T, db *storage.DB, name string) model.Secret {
	t.Helper()
	s, err := storage.NewSecretRepo(db, make([]byte, crypto.KeySize)).Create(context.Background(), name, []byte("value-of-"+name))
	if err != nil {
		t.Fatalf("create secret %q: %v", name, err)
	}
	return s
}

func TestTokenAuthenticateRejectsWrongRevokedAndExpired(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewTokenRepo(db)

	plaintext, mt, err := repo.Create(ctx, "ci runner", nil)
	if err != nil || mt.Description != "ci runner" {
		t.Fatalf("Create = %+v, %v", mt, err)
	}
	got, grants, err := repo.Authenticate(ctx, plaintext)
	if err != nil || got.ID != mt.ID || len(grants) != 0 || got.LastUsedAt == nil {
		t.Fatalf("Authenticate = %+v, %v, %v", got, grants, err)
	}
	if _, _, err := repo.Authenticate(ctx, plaintext+"x"); !errors.Is(err, authtoken.ErrInvalidToken) {
		t.Fatalf("wrong token: %v", err)
	}

	past := time.Now().Add(-time.Minute)
	expired, _, err := repo.Create(ctx, "expired", &past)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.Authenticate(ctx, expired); !errors.Is(err, authtoken.ErrInvalidToken) {
		t.Fatalf("expired token: %v", err)
	}

	if err := repo.Revoke(ctx, mt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.Authenticate(ctx, plaintext); !errors.Is(err, authtoken.ErrInvalidToken) {
		t.Fatalf("revoked token: %v", err)
	}
}

func TestTokenGrantsUseExplicitOrDerivedNames(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewTokenRepo(db)
	dbPass := createTestSecret(t, db, "db-password")
	apiKey := createTestSecret(t, db, "api-key")
	_, mt, err := repo.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := repo.AddGrant(ctx, mt.ID, dbPass.ID, "read", "POSTGRES_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	if err := repo.AddGrant(ctx, mt.ID, apiKey.ID, "write", ""); err != nil {
		t.Fatal(err)
	}
	env, err := repo.EnvGrants(ctx, mt.ID)
	if err != nil || len(env) != 2 {
		t.Fatalf("EnvGrants = %+v, %v", env, err)
	}
	names := map[int64]string{}
	for _, g := range env {
		names[g.SecretID] = g.EnvName
	}
	if names[dbPass.ID] != "POSTGRES_PASSWORD" || names[apiKey.ID] != "API_KEY" {
		t.Fatalf("env names = %v", names)
	}

	// Granting the same secret again replaces the grant rather than
	// conflicting with itself.
	if err := repo.AddGrant(ctx, mt.ID, apiKey.ID, "read", ""); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	grants, _ := repo.ListGrants(ctx, mt.ID)
	if len(grants) != 2 {
		t.Fatalf("grants after re-grant = %+v", grants)
	}
}

func TestTokenGrantProblemsAreRefused(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewTokenRepo(db)
	a := createTestSecret(t, db, "a")
	b := createTestSecret(t, db, "b")
	_, mt, err := repo.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AddGrant(ctx, mt.ID, a.ID, "read", "SAME"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		err  error
		want error
	}{
		{"invalid env name", repo.AddGrant(ctx, mt.ID, b.ID, "read", "bad-name"), storage.ErrInvalidEnvName},
		{"name taken on this token", repo.AddGrant(ctx, mt.ID, b.ID, "read", "SAME"), storage.ErrEnvNameTaken},
		{"missing secret", repo.AddGrant(ctx, mt.ID, 9999, "read", "X"), storage.ErrNotFound},
		{"missing secret, derived name", repo.AddGrant(ctx, mt.ID, 9999, "read", ""), storage.ErrSecretNotFound},
		{"missing token", repo.AddGrant(ctx, 9999, b.ID, "read", "X"), storage.ErrNotFound},
	}
	for _, c := range cases {
		if !errors.Is(c.err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, c.err, c.want)
		}
	}
}

func TestDeletingASecretRemovesItsGrants(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewTokenRepo(db)
	s := createTestSecret(t, db, "doomed")
	_, mt, err := repo.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AddGrant(ctx, mt.ID, s.ID, "read", ""); err != nil {
		t.Fatal(err)
	}
	if err := storage.NewSecretRepo(db, make([]byte, crypto.KeySize)).Delete(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if grants, err := repo.ListGrants(ctx, mt.ID); err != nil || len(grants) != 0 {
		t.Fatalf("grants after delete = %+v, %v", grants, err)
	}
}
