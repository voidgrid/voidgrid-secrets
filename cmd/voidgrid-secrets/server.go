package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
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
	"github.com/voidgrid/voidgrid-secrets/internal/httpsec"
	"github.com/voidgrid/voidgrid-secrets/internal/model"
	"github.com/voidgrid/voidgrid-secrets/internal/recovery"
	"github.com/voidgrid/voidgrid-secrets/internal/selfexport"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
	"github.com/voidgrid/voidgrid-secrets/internal/storage"
	"github.com/voidgrid/voidgrid-secrets/internal/version"
	"github.com/voidgrid/voidgrid-secrets/internal/web"
)

// runServer loads the root key, opens the SQLite database, runs migrations, wires
// up every repository and handler, and serves the combined API + web UI
// router until the process is killed.
func runServer(cfg config.Config) error {
	rootKey, err := crypto.LoadRootKey(cfg.RootKeyPath)
	if err != nil {
		return fmt.Errorf("load root key (run 'voidgrid-secrets keygen' first if this is a new deployment): %w", err)
	}

	if err := storage.CheckLegacy(cfg.DBPath); err != nil {
		return err
	}
	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if err := db.Migrate(context.Background()); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	publishSelf(cfg.ExportDir)
	if problems, err := db.CheckIntegrity(context.Background()); err != nil {
		log.Printf("database check could not run: %v", err)
	} else {
		for _, p := range problems {
			log.Printf("DATABASE PROBLEM: %s", p)
		}
	}

	auditRepo := storage.NewAuditRepo(db)
	secretRepo := storage.NewSecretRepo(db, rootKey)
	tokenRepo := storage.NewTokenRepo(db)
	userRepo := storage.NewUserRepo(db, rootKey)
	sessionRepo := storage.NewSessionRepo(db)
	authConfigRepo := storage.NewAuthConfigRepo(db, rootKey)
	recoveryCodeRepo := storage.NewRecoveryCodeRepo(db)
	resetRepo := storage.NewResetRepo(db, rootKey)
	groupRepo := storage.NewGroupRepo(db)

	go pruneAuditLog(context.Background(), auditRepo)

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
	// 10 failures in 15 minutes locks sign-in (and, separately, recovery)
	// out until the 15 minutes are up.
	limiter := session.NewAttemptLimiter(10, 15*time.Minute)
	loginService := &session.LoginService{
		Users:          userRepo,
		Sessions:       sessionRepo,
		VerifyPassword: crypto.VerifyPassword,
		ValidateTOTP:   totp.Validate,
		Limiter:        limiter,
		Audit:          auditRepo,
	}
	recoveryService := newRecoveryService(userRepo, resetRepo, recoveryCodeRepo, sessionRepo, auditRepo)
	recoveryService.Limiter = limiter

	apiHandler := api.NewRouter(api.Deps{
		SetupChecker:   authConfigRepo,
		TokenAuth:      tokenRepo,
		SessionAuth:    sessionRepo,
		SetupHandler:   api.NewSetupHandler(wizard, oidcProvider),
		AuthHandler:    api.NewAuthHandler(loginService, sessionRepo, auditRepo),
		SecretsHandler: api.NewSecretsHandler(secretRepo, auditRepo),
		EnvHandler:     api.NewEnvHandler(tokenRepo, secretRepo, auditRepo),
		RecoverHandler: api.NewRecoverHandler(recoveryService),
		TokensHandler:  api.NewTokensHandler(tokenRepo, auditRepo),
		GroupsHandler:  api.NewGroupsHandler(groupRepo, auditRepo),
		AuditHandler:   api.NewAuditHandler(auditRepo),
		Audit:          auditRepo,
	})

	webHandler := web.NewRouter(web.Deps{
		SetupChecker: authConfigRepo,
		SessionAuth:  sessionRepo,
		Setup:        web.NewSetupHandler(wizard, oidcProvider),
		Auth:         web.NewAuthHandler(loginService, sessionRepo, authConfigRepo, oidcProvider, userRepo, wizard, auditRepo),
		Recover:      web.NewRecoverHandler(recoveryService),
		Secrets:      web.NewSecretsHandler(secretRepo, tokenRepo, auditRepo),
		Tokens:       web.NewTokensHandler(tokenRepo, secretRepo, groupRepo, auditRepo),
		Groups:       web.NewGroupsHandler(groupRepo, secretRepo, auditRepo),
		Audit:        web.NewAuditHandler(auditRepo, tokenRepo),
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

	fmt.Printf("voidgrid-secrets %s listening on %s\n", version.Version, cfg.ListenAddr)
	srv := &http.Server{
		Addr: cfg.ListenAddr,
		// audit.Middleware attaches the client address to every audit
		// entry recorded while handling a request.
		Handler: audit.Middleware(httpsec.Middleware(cfg.HTTPAllowedNets)(root)),
		// Bound how long a client can hold a connection without finishing
		// a request (slowloris). Every request here is small and quick.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	// This process is PID 1 in the container: handle SIGTERM (docker stop)
	// by finishing in-flight requests and closing the database cleanly, so
	// its write-ahead log is checkpointed.
	stop, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	select {
	case err := <-serveErr:
		return err
	case <-stop.Done():
		log.Printf("shutting down")
		ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

// publishSelf copies this executable into dir (if set) so other containers
// can mount it and use `voidgrid-secrets run`. Failing to do so is logged,
// never fatal: the server's own job doesn't depend on it.
func publishSelf(dir string) {
	if dir == "" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		log.Printf("export: cannot find this executable: %v", err)
		return
	}
	res, err := selfexport.Publish(exe, dir)
	switch {
	case err != nil:
		log.Printf("export: could not publish the executable to %s (consumers can still use a helper container): %v", dir, err)
	case res.Updated:
		log.Printf("export: published %s for consumers to mount", res.Path)
	}
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

	// A pending config (OIDC saved, operator not signed in yet) is loaded
	// too, so a restart mid-setup doesn't strand the sign-in step.
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

// auditRetention is how long audit entries are kept.
const auditRetention = 14 * 24 * time.Hour

// pruneAuditLog deletes audit entries older than auditRetention now and
// then once a day.
func pruneAuditLog(ctx context.Context, repo *storage.AuditRepo) {
	for {
		n, err := repo.Prune(ctx, time.Now().Add(-auditRetention))
		switch {
		case err != nil:
			log.Printf("audit: prune failed: %v", err)
		case n > 0:
			audit.Record(ctx, repo, audit.Event{
				Actor: audit.System(), Action: audit.AuditPruned, ResourceType: "audit",
				Details: map[string]string{"deleted": strconv.FormatInt(n, 10), "older_than_days": "14"},
			})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

// newRecoveryService builds the account recovery service, shared by the
// server and the `recover` command.
func newRecoveryService(users *storage.UserRepo, resets *storage.ResetRepo, codes *storage.RecoveryCodeRepo,
	sessions *storage.SessionRepo, auditLog audit.Logger,
) *recovery.Service {
	return &recovery.Service{
		Users: users, Resets: resets, RecoveryCodes: codes, Sessions: sessions,
		GenerateTOTP: totp.Generate, ValidateTOTP: totp.Validate, HashPassword: crypto.HashPassword,
		Audit: auditLog,
	}
}
