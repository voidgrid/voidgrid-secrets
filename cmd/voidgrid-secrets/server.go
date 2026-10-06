package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/voidgrid/voidgrid-secrets/internal/api"
	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/recoverycode"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/session"
	"github.com/voidgrid/voidgrid-secrets/internal/auth/totp"
	"github.com/voidgrid/voidgrid-secrets/internal/config"
	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
	"github.com/voidgrid/voidgrid-secrets/internal/web"
)

// runServer loads the root key, connects to rqlite, runs migrations, wires
// up every repository and handler, and serves the combined API + web UI
// router until the process is killed.
func runServer(cfg config.Config) error {
	rootKey, err := crypto.LoadRootKey(cfg.RootKeyPath)
	if err != nil {
		return fmt.Errorf("load root key (run 'voidgrid-secrets keygen' first if this is a new deployment): %w", err)
	}

	db, err := storage.Open(cfg.RqliteAddr)
	if err != nil {
		return fmt.Errorf("connect to rqlite: %w", err)
	}
	defer db.Close()

	if err := db.Migrate(context.Background()); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	secretRepo := storage.NewSecretRepo(db, rootKey)
	upgraded, err := secretRepo.UpgradeEncryption(context.Background())
	if err != nil {
		return fmt.Errorf("upgrade secret encryption: %w", err)
	}
	if upgraded > 0 {
		log.Printf("storage: re-encrypted %d secret(s) to bind each to its id", upgraded)
	}
	shareRepo := storage.NewShareRepo(db)
	tokenRepo := storage.NewTokenRepo(db)
	userRepo := storage.NewUserRepo(db, rootKey)
	groupRepo := storage.NewGroupRepo(db)
	sessionRepo := storage.NewSessionRepo(db)
	authConfigRepo := storage.NewAuthConfigRepo(db, rootKey)
	auditRepo := storage.NewAuditRepo(db)
	recoveryCodeRepo := storage.NewRecoveryCodeRepo(db)

	oidcProvider := loadOIDCProvider(context.Background(), authConfigRepo)

	wizard := &setup.Wizard{
		Users:                 userRepo,
		AuthConfig:            authConfigRepo,
		RecoveryCodes:         recoveryCodeRepo,
		GenerateTOTP:          totp.Generate,
		ValidateTOTP:          totp.Validate,
		HashPassword:          crypto.HashPassword,
		GenerateRecoveryCodes: recoverycode.Generate,
		HashRecoveryCode:      crypto.HashToken,
	}
	loginService := &session.LoginService{
		Users:          userRepo,
		Sessions:       sessionRepo,
		RecoveryCodes:  recoveryCodeRepo,
		VerifyPassword: crypto.VerifyPassword,
		ValidateTOTP:   totp.Validate,
		// 10 failures in 15 minutes locks a username out of password and
		// recovery-code login until the 15 minutes are up.
		Limiter: session.NewAttemptLimiter(10, 15*time.Minute),
	}

	apiHandler := api.NewRouter(api.Deps{
		SetupChecker:   authConfigRepo,
		TokenAuth:      tokenRepo,
		SessionAuth:    sessionRepo,
		SetupHandler:   api.NewSetupHandler(wizard, oidcProvider),
		AuthHandler:    api.NewAuthHandler(loginService, sessionRepo),
		SecretsHandler: api.NewSecretsHandler(secretRepo),
		EnvHandler:     api.NewEnvHandler(tokenRepo, secretRepo, auditRepo),
		SharesHandler:  api.NewSharesHandler(secretRepo, shareRepo),
		UsersHandler:   api.NewUsersHandler(userRepo),
		GroupsHandler:  api.NewGroupsHandler(groupRepo),
		TokensHandler:  api.NewTokensHandler(tokenRepo),
	})

	webHandler := web.NewRouter(web.Deps{
		SetupChecker: authConfigRepo,
		SessionAuth:  sessionRepo,
		Setup:        web.NewSetupHandler(wizard, oidcProvider),
		Auth:         web.NewAuthHandler(loginService, sessionRepo, authConfigRepo, oidcProvider, userRepo, recoveryCodeRepo),
		Secrets:      web.NewSecretsHandler(secretRepo, shareRepo, auditRepo),
		Users:        web.NewUsersHandler(userRepo),
		Groups:       web.NewGroupsHandler(groupRepo),
		Tokens:       web.NewTokensHandler(tokenRepo),
	})

	root := chi.NewMux()
	// The JSON API and its auto-served docs/spec routes take priority;
	// everything else falls through to the web UI.
	root.Handle("/api/*", apiHandler)
	root.Handle("/openapi.json", apiHandler)
	root.Handle("/openapi.yaml", apiHandler)
	root.Handle("/docs", apiHandler)
	root.Handle("/docs/*", apiHandler)
	root.Handle("/schemas/*", apiHandler)
	root.Handle("/*", webHandler)

	fmt.Printf("voidgrid-secrets listening on %s\n", cfg.ListenAddr)
	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: root,
		// Bound how long a client can hold a connection without finishing
		// a request (slowloris). Every request here is small and quick.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return srv.ListenAndServe()
}

// loadOIDCProvider builds the deployment's OIDC client at startup, if
// setup already completed with OIDC chosen. A failure here (e.g. the
// issuer is temporarily unreachable) is logged, not fatal: the server
// must still start and serve recovery-code login either way - that's the
// entire point of recovery codes existing. The provider can also be set
// later, directly, by a successful SetupOIDC call.
func loadOIDCProvider(ctx context.Context, authConfigRepo *storage.AuthConfigRepo) *oidcclient.Provider {
	provider := &oidcclient.Provider{}

	complete, err := authConfigRepo.IsComplete(ctx)
	if err != nil || !complete {
		return provider
	}
	cfg, err := authConfigRepo.Get(ctx)
	if err != nil || cfg.AuthMethod != model.AuthOIDC {
		return provider
	}

	client, err := oidcclient.New(ctx, oidcclient.Config{
		Issuer:       cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURI:  cfg.OIDCRedirectURI,
	})
	if err != nil {
		log.Printf("oidc: failed to initialize at startup - OIDC login will be unavailable until this server is restarted with a reachable issuer; use recovery-code login until then: %v", err)
		return provider
	}

	provider.Set(client)
	return provider
}
