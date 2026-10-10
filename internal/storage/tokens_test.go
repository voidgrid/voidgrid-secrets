package storage_test

import (
	"context"
	"errors"
	"reflect"
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

func TestRemoveGrantTakesOnlyThatGrant(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewTokenRepo(db)
	keep, drop := createTestSecret(t, db, "keep"), createTestSecret(t, db, "drop")
	_, mt, err := repo.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := repo.Create(ctx, "other", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []struct{ tok, sec int64 }{{mt.ID, keep.ID}, {mt.ID, drop.ID}, {other.ID, drop.ID}} {
		if err := repo.AddGrant(ctx, g.tok, g.sec, "read", ""); err != nil {
			t.Fatal(err)
		}
	}

	if err := repo.RemoveGrant(ctx, mt.ID, drop.ID); err != nil {
		t.Fatalf("RemoveGrant: %v", err)
	}
	grants, err := repo.ListGrants(ctx, mt.ID)
	if err != nil || len(grants) != 1 || grants[0].SecretID != keep.ID {
		t.Fatalf("grants after remove = %+v, %v", grants, err)
	}
	if env, err := repo.EnvGrants(ctx, mt.ID); err != nil || len(env) != 1 || env[0].SecretID != keep.ID {
		t.Fatalf("env grants after remove = %+v, %v", env, err)
	}
	if g, err := repo.ListGrants(ctx, other.ID); err != nil || len(g) != 1 {
		t.Fatalf("another token's grant on the same secret was touched: %+v, %v", g, err)
	}
	if err := repo.RemoveGrant(ctx, mt.ID, drop.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("removing twice = %v, want ErrNotFound", err)
	}
	if err := repo.RemoveGrant(ctx, 9999, keep.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown token = %v, want ErrNotFound", err)
	}
}

func TestSetGrantsReplacesTheWholeSetAtomically(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewTokenRepo(db)
	a, b, c := createTestSecret(t, db, "a-key"), createTestSecret(t, db, "b-key"), createTestSecret(t, db, "c-key")
	_, mt, err := repo.Create(ctx, "svc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AddGrant(ctx, mt.ID, a.ID, "read", ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.AddGrant(ctx, mt.ID, b.ID, "read", "B_OLD"); err != nil {
		t.Fatal(err)
	}

	change, err := repo.SetGrants(ctx, mt.ID, []storage.GrantSpec{
		{SecretID: a.ID, Permission: "read"},                    // unchanged
		{SecretID: b.ID, Permission: "write", EnvName: "B_NEW"}, // changed
		{SecretID: c.ID, Permission: "read"},                    // added
	})
	if err != nil {
		t.Fatalf("SetGrants: %v", err)
	}
	if !reflect.DeepEqual(change, storage.GrantChange{Added: []int64{c.ID}, Changed: []int64{b.ID}}) {
		t.Fatalf("change = %+v", change)
	}
	grants, _ := repo.ListGrants(ctx, mt.ID)
	if len(grants) != 3 {
		t.Fatalf("grants = %+v", grants)
	}

	change, err = repo.SetGrants(ctx, mt.ID, []storage.GrantSpec{{SecretID: c.ID, Permission: "read"}})
	if err != nil || !reflect.DeepEqual(change, storage.GrantChange{Removed: []int64{a.ID, b.ID}}) {
		t.Fatalf("removing: %+v, %v", change, err)
	}

	// Anything invalid leaves the grants exactly as they were.
	before, _ := repo.ListGrants(ctx, mt.ID)
	bad := []struct {
		name  string
		specs []storage.GrantSpec
		want  error
	}{
		{"bad permission", []storage.GrantSpec{{SecretID: a.ID, Permission: "admin"}}, storage.ErrInvalidPermission},
		{"bad env name", []storage.GrantSpec{{SecretID: a.ID, Permission: "read", EnvName: "lower"}}, storage.ErrInvalidEnvName},
		{"explicit collision", []storage.GrantSpec{{SecretID: a.ID, Permission: "read", EnvName: "X"}, {SecretID: b.ID, Permission: "read", EnvName: "X"}}, storage.ErrEnvNameTaken},
		{"derived collision", []storage.GrantSpec{{SecretID: a.ID, Permission: "read"}, {SecretID: b.ID, Permission: "read", EnvName: "A_KEY"}}, storage.ErrEnvNameTaken},
		{"unknown secret", []storage.GrantSpec{{SecretID: a.ID, Permission: "read"}, {SecretID: 9999, Permission: "read"}}, storage.ErrSecretNotFound},
	}
	for _, c := range bad {
		if _, err := repo.SetGrants(ctx, mt.ID, c.specs); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if after, _ := repo.ListGrants(ctx, mt.ID); !reflect.DeepEqual(after, before) {
		t.Fatalf("a refused change altered the grants:\nbefore %+v\nafter  %+v", before, after)
	}
	if _, err := repo.SetGrants(ctx, 9999, nil); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
	if _, err := repo.SetGrants(ctx, mt.ID, nil); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	if after, _ := repo.ListGrants(ctx, mt.ID); len(after) != 0 {
		t.Fatalf("grants after clearing = %+v", after)
	}
}

func TestGrantableToHidesGrantedRevokedAndExpiredTokens(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	repo := storage.NewTokenRepo(db)
	s := createTestSecret(t, db, "shared")
	other := createTestSecret(t, db, "unrelated")
	mk := func(desc string, exp *time.Time) model.MachineToken {
		_, mt, err := repo.Create(ctx, desc, exp)
		if err != nil {
			t.Fatal(err)
		}
		return mt
	}
	free, granted, revoked := mk("free", nil), mk("granted", nil), mk("revoked", nil)
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	expired, later := mk("expired", &past), mk("later", &future)
	onOther := mk("on-other-secret", nil)

	if err := repo.AddGrant(ctx, granted.ID, s.ID, "read", ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.AddGrant(ctx, onOther.ID, other.ID, "read", ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}

	got, err := repo.GrantableTo(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, mt := range got {
		ids = append(ids, mt.ID)
	}
	want := []int64{free.ID, later.ID, onOther.ID}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("grantable = %v, want %v (not granted %d, revoked %d, expired %d)", ids, want, granted.ID, revoked.ID, expired.ID)
	}
}
