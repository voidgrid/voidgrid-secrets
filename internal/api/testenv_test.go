package api_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/api"
	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/recoverycode"
	gosession "github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	gototp "github.com/voidgrid/voidgrid-secrets/internal/auth/totp"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/recovery"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
)

const testSetupToken = "vgs_setup_test" //nolint:gosec // fake test fixture, not a real credential

// env is a full, real stack (SQLite + storage + HTTP router) for exercising
// the API end-to-end, per the project's testing strategy: these
// boundary/security tests use real components, not mocks.
type env struct {
	handler        http.Handler
	db             *storage.DB
	rootKey        []byte
	secrets        *storage.SecretRepo
	tokens         *storage.TokenRepo
	users          *storage.UserRepo
	sessions       *storage.SessionRepo
	recoveryCodes  *storage.RecoveryCodeRepo
	recovery       *recovery.Service
	authConfigRepo *storage.AuthConfigRepo
}

// newEnv opens a fresh SQLite database, wires up every repo/handler, and
// returns a router. If completeSetup is true, setup is marked complete
// directly (bypassing the wizard) for tests that exercise other behavior.
func newEnv(t *testing.T, completeSetup bool) env {
	t.Helper()

	db, err := storage.Open(filepath.Join(t.TempDir(), "voidgrid.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	rootKey := make([]byte, crypto.KeySize)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	tokenRepo := storage.NewTokenRepo(db)
	userRepo := storage.NewUserRepo(db, rootKey)
	sessionRepo := storage.NewSessionRepo(db)
	authConfigRepo := storage.NewAuthConfigRepo(db, rootKey)
	recoveryCodeRepo := storage.NewRecoveryCodeRepo(db)

	if completeSetup {
		if err := authConfigRepo.CompletePasswordTOTP(context.Background()); err != nil {
			t.Fatalf("CompletePasswordTOTP: %v", err)
		}
	}

	auditRepo := storage.NewAuditRepo(db)

	wizard := &setup.Wizard{
		Audit:                 auditRepo,
		SetupToken:            testSetupToken,
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
		Audit:          auditRepo,
		Users:          userRepo,
		Sessions:       sessionRepo,
		VerifyPassword: crypto.VerifyPassword,
		ValidateTOTP:   gototp.Validate,
	}

	recoveryService := &recovery.Service{
		Users: userRepo, Resets: storage.NewResetRepo(db, rootKey), RecoveryCodes: recoveryCodeRepo, Sessions: sessionRepo,
		GenerateTOTP: gototp.Generate, ValidateTOTP: gototp.Validate, HashPassword: crypto.HashPassword, Audit: auditRepo,
	}

	handler := api.NewRouter(api.Deps{
		SetupChecker:   authConfigRepo,
		TokenAuth:      tokenRepo,
		SessionAuth:    sessionRepo,
		SetupHandler:   api.NewSetupHandler(wizard, &oidcclient.Provider{}),
		AuthHandler:    api.NewAuthHandler(loginService, sessionRepo, auditRepo),
		SecretsHandler: api.NewSecretsHandler(secretRepo, auditRepo),
		EnvHandler:     api.NewEnvHandler(tokenRepo, secretRepo, auditRepo),
		RecoverHandler: api.NewRecoverHandler(recoveryService),
		TokensHandler:  api.NewTokensHandler(tokenRepo, auditRepo),
		GroupsHandler:  api.NewGroupsHandler(storage.NewGroupRepo(db), auditRepo),
		AuditHandler:   api.NewAuditHandler(auditRepo),
		Audit:          auditRepo,
	})

	return env{
		handler:        handler,
		db:             db,
		rootKey:        rootKey,
		secrets:        secretRepo,
		tokens:         tokenRepo,
		users:          userRepo,
		sessions:       sessionRepo,
		recoveryCodes:  recoveryCodeRepo,
		recovery:       recoveryService,
		authConfigRepo: authConfigRepo,
	}
}

// ownerCookie creates the account (password+TOTP, already enrolled) if it
// doesn't exist, and returns a session cookie for it.
func ownerCookie(t *testing.T, e env) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	user, err := e.users.Get(ctx)
	if err != nil {
		hash, herr := crypto.HashPassword(ownerPassword)
		if herr != nil {
			t.Fatal(herr)
		}
		if user, err = e.users.SetupPassword(ctx, "owner", hash); err != nil {
			t.Fatalf("SetupPassword: %v", err)
		}
		if err := e.users.SetTOTPSecret(ctx, ownerTOTPSecret); err != nil {
			t.Fatal(err)
		}
	}
	token, _, err := e.sessions.Create(ctx, user.ID, gosession.DefaultTTL)
	if err != nil {
		t.Fatalf("sessions.Create: %v", err)
	}
	return &http.Cookie{Name: gosession.CookieName, Value: token} //nolint:gosec // request cookie in a test; Secure/HttpOnly/SameSite are response-cookie attributes and don't apply here
}

const (
	ownerPassword   = "correct horse battery staple" //nolint:gosec // fake test fixture, not a real credential
	ownerTOTPSecret = "JBSWY3DPEHPK3PXP"             //nolint:gosec // fake test fixture, not a real credential
)
