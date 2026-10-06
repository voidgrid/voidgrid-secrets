package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/voidgrid/voidgrid-secrets/internal/api"
	"github.com/voidgrid/voidgrid-secrets/internal/audit"
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

	violations, err := db.ForeignKeyViolations(context.Background())
	if err != nil {
		return err
	}
	for _, v := range violations {
		log.Printf("storage: existing row breaks a foreign key (written before enforcement was enabled): %s", v)
	}

	auditRepo := storage.NewAuditRepo(db)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	upgraded, err := secretRepo.UpgradeEncryption(context.Background())
	if err != nil {
		return fmt.Errorf("upgrade secret encryption: %w", err)
	}
	if upgraded > 0 {
		log.Printf("storage: re-encrypted %d secret(s) to bind each to its id", upgraded)
		audit.Record(context.Background(), auditRepo, audit.Event{
			Actor: audit.System(), Action: audit.EncryptionUpgraded, ResourceType: "secret",
			Details: map[string]string{"count": strconv.Itoa(upgraded)},
		})
	}
	shareRepo := storage.NewShareRepo(db)
	tokenRepo := storage.NewTokenRepo(db)
	userRepo := storage.NewUserRepo(db, rootKey)
	groupRepo := storage.NewGroupRepo(db)
	sessionRepo := storage.NewSessionRepo(db)
	authConfigRepo := storage.NewAuthConfigRepo(db, rootKey)
	recoveryCodeRepo := storage.NewRecoveryCodeRepo(db)

	oidcProvider := loadOIDCProvider(context.Background(), authConfigRepo)

	setupToken, err := setupTokenIfNeeded(context.Background(), authConfigRepo)
	if err != nil {
		return err
	}

	wizard := &setup.Wizard{
		SetupToken:            setupToken,
		Users:                 userRepo,
		AuthConfig:            authConfigRepo,
		RecoveryCodes:         recoveryCodeRepo,
		GenerateTOTP:          totp.Generate,
		ValidateTOTP:          totp.Validate,
		HashPassword:          crypto.HashPassword,
		GenerateRecoveryCodes: recoverycode.Generate,
		HashRecoveryCode:      crypto.HashToken,
		Audit:                 auditRepo,
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
		Audit:   auditRepo,
	}

	apiHandler := api.NewRouter(api.Deps{
		SetupChecker:   authConfigRepo,
		TokenAuth:      tokenRepo,
		SessionAuth:    sessionRepo,
		SetupHandler:   api.NewSetupHandler(wizard, oidcProvider),
		AuthHandler:    api.NewAuthHandler(loginService, sessionRepo, auditRepo),
		SecretsHandler: api.NewSecretsHandler(secretRepo, auditRepo),
		EnvHandler:     api.NewEnvHandler(tokenRepo, secretRepo, auditRepo),
		SharesHandler:  api.NewSharesHandler(secretRepo, shareRepo, auditRepo),
		UsersHandler:   api.NewUsersHandler(userRepo, auditRepo),
		GroupsHandler:  api.NewGroupsHandler(groupRepo, auditRepo),
		TokensHandler:  api.NewTokensHandler(tokenRepo, auditRepo),
		AuditHandler:   api.NewAuditHandler(auditRepo),
		Audit:          auditRepo,
	})

	webHandler := web.NewRouter(web.Deps{
		SetupChecker: authConfigRepo,
		SessionAuth:  sessionRepo,
		Setup:        web.NewSetupHandler(wizard, oidcProvider),
		Auth:         web.NewAuthHandler(loginService, sessionRepo, authConfigRepo, oidcProvider, userRepo, recoveryCodeRepo, auditRepo),
		Secrets:      web.NewSecretsHandler(secretRepo, shareRepo, auditRepo),
		Users:        web.NewUsersHandler(userRepo, auditRepo),
		Groups:       web.NewGroupsHandler(groupRepo, auditRepo),
		Tokens:       web.NewTokensHandler(tokenRepo, auditRepo),
		Audit:        web.NewAuditHandler(auditRepo),
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
		Addr: cfg.ListenAddr,
		// audit.Middleware attaches the client address to every audit
		// entry recorded while handling a request.
		Handler: audit.Middleware(root),
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
// setupTokenIfNeeded generates the one-time setup token while setup is
// incomplete and prints it to the log, which only the operator can read.
// The setup wizard refuses every step without it. It lives only in this
// process: a restart prints a new one.
func setupTokenIfNeeded(ctx context.Context, authConfigRepo *storage.AuthConfigRepo) (string, error) {
	complete, err := authConfigRepo.IsComplete(ctx)
	if err != nil {
		return "", fmt.Errorf("check setup status: %w", err)
	}
	if complete {
		return "", nil
	}
	token, err := crypto.GenerateOpaqueToken("vgs_setup_")
	if err != nil {
		return "", fmt.Errorf("generate setup token: %w", err)
	}
	log.Printf("setup is not complete. Open /setup in a browser and enter this setup token (valid until this server restarts):")
	log.Printf("setup token: %s", token)
	return token, nil
}

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
