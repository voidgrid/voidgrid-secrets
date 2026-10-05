package api_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/api"
	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/recoverycode"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	gototp "github.com/voidgrid/voidgrid-secrets/internal/auth/totp"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

// env is a full, real stack (rqlite + storage + HTTP router) for exercising
// the API end-to-end, per the project's testing strategy: these
// boundary/security tests use real components, not mocks.
type env struct {
	handler        http.Handler
	db             *storage.DB
	rootKey        []byte
	secrets        *storage.SecretRepo
	shares         *storage.ShareRepo
	tokens         *storage.TokenRepo
	users          *storage.UserRepo
	groups         *storage.GroupRepo
	sessions       *storage.SessionRepo
	authConfigRepo *storage.AuthConfigRepo
	// baseURL is the test rqlited's HTTP address, for assertions that
	// query tables directly (e.g. audit_log).
	baseURL string
}

// newEnv starts a fresh rqlited instance, wires up every repo/handler, and
// returns a router. If completeSetup is true, setup is marked complete
// directly (bypassing the wizard) for tests that exercise other behavior.
func newEnv(t *testing.T, completeSetup bool) env {
	t.Helper()

	if _, err := exec.LookPath("rqlited"); err != nil {
		t.Skip("rqlited not found in PATH; skipping integration test")
	}

	httpPort := freePort(t)
	raftPort := freePort(t)
	dataDir := t.TempDir()
	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	cmd := exec.Command("rqlited", //nolint:gosec // fixed binary name + test-generated args
		"-http-addr", httpAddr,
		"-raft-addr", fmt.Sprintf("127.0.0.1:%d", raftPort),
		dataDir,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rqlited: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	baseURL := "http://" + httpAddr
	waitForReady(t, baseURL)

	db, err := storage.Open(baseURL)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	rootKey := make([]byte, crypto.KeySize)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	shareRepo := storage.NewShareRepo(db)
	tokenRepo := storage.NewTokenRepo(db)
	userRepo := storage.NewUserRepo(db, rootKey)
	groupRepo := storage.NewGroupRepo(db)
	sessionRepo := storage.NewSessionRepo(db)
	authConfigRepo := storage.NewAuthConfigRepo(db, rootKey)
	recoveryCodeRepo := storage.NewRecoveryCodeRepo(db)

	if completeSetup {
		if err := authConfigRepo.CompletePasswordTOTP(context.Background()); err != nil {
			t.Fatalf("CompletePasswordTOTP: %v", err)
		}
	}

	wizard := &setup.Wizard{
		Users:                 userRepo,
		AuthConfig:            authConfigRepo,
		RecoveryCodes:         recoveryCodeRepo,
		GenerateTOTP:          gototp.Generate,
		ValidateTOTP:          gototp.Validate,
		HashPassword:          crypto.HashPassword,
		GenerateRecoveryCodes: recoverycode.Generate,
		HashRecoveryCode:      crypto.HashToken,
	}
	loginService := &gosession.LoginService{
		Users:          userRepo,
		Sessions:       sessionRepo,
		VerifyPassword: crypto.VerifyPassword,
		ValidateTOTP:   gototp.Validate,
	}

	handler := api.NewRouter(api.Deps{
		SetupChecker:   authConfigRepo,
		TokenAuth:      tokenRepo,
		SessionAuth:    sessionRepo,
		SetupHandler:   api.NewSetupHandler(wizard, &oidcclient.Provider{}),
		AuthHandler:    api.NewAuthHandler(loginService, sessionRepo),
		SecretsHandler: api.NewSecretsHandler(secretRepo),
		EnvHandler:     api.NewEnvHandler(tokenRepo, secretRepo, storage.NewAuditRepo(db)),
		SharesHandler:  api.NewSharesHandler(secretRepo, shareRepo),
		UsersHandler:   api.NewUsersHandler(userRepo),
		GroupsHandler:  api.NewGroupsHandler(groupRepo),
		TokensHandler:  api.NewTokensHandler(tokenRepo),
	})

	return env{
		handler:        handler,
		db:             db,
		rootKey:        rootKey,
		secrets:        secretRepo,
		shares:         shareRepo,
		tokens:         tokenRepo,
		users:          userRepo,
		groups:         groupRepo,
		sessions:       sessionRepo,
		authConfigRepo: authConfigRepo,
		baseURL:        baseURL,
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/readyz") //nolint:gosec // baseURL is test-local, not attacker-controlled
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("rqlited at %s did not become ready in time", baseURL)
}
