// Package oidc wraps zitadel/oidc's relying-party client for the OIDC web
// authentication method: starting the auth-code+PKCE flow and handling the
// provider's callback.
//
// Unlike the password+TOTP path, this package's construction (New)
// performs real OIDC discovery against the configured issuer and so can
// only be meaningfully tested against a live or faked IdP; its test
// coverage here is limited to what's verifiable without one (error
// handling on a bad issuer). The password+TOTP path remains the more
// thoroughly covered of the two web auth methods.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Config is the OIDC provider configuration, as stored by the setup wizard
// (see internal/model.AuthConfig).
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// Client wraps a configured OIDC relying party.
type Client struct {
	rp rp.RelyingParty
}

// New performs OIDC discovery against cfg.Issuer and returns a ready
// Client. It requires network access to the issuer and will fail fast on
// an unreachable or invalid one.
func New(ctx context.Context, cfg Config) (*Client, error) {
	hashKey := make([]byte, 32)
	if _, err := rand.Read(hashKey); err != nil {
		return nil, fmt.Errorf("oidc: generate cookie hash key: %w", err)
	}
	encryptKey := make([]byte, 32)
	if _, err := rand.Read(encryptKey); err != nil {
		return nil, fmt.Errorf("oidc: generate cookie encrypt key: %w", err)
	}
	cookieHandler := httphelper.NewCookieHandler(hashKey, encryptKey)

	relyingParty, err := rp.NewRelyingPartyOIDC(
		ctx, cfg.Issuer, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI,
		[]string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
		rp.WithPKCE(cookieHandler),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover issuer %q: %w", cfg.Issuer, err)
	}

	return &Client{rp: relyingParty}, nil
}

// State returns a fresh random state value for the auth-code flow.
func State() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// LoginHandler returns an http.HandlerFunc that starts the auth-code+PKCE
// flow: it generates a fresh state value, sets the cookies needed to
// verify it (and the PKCE code verifier) on callback, and redirects to
// the provider. Unlike calling AuthURL directly, this also sets those
// cookies - skipping it is the easy way to end up with a CallbackHandler
// that always fails to validate state/PKCE.
func (c *Client) LoginHandler() http.HandlerFunc {
	return rp.AuthURLHandler(State, c.rp)
}

// CallbackHandler returns an http.HandlerFunc for the OIDC provider's
// redirect callback. It completes the code exchange (validating the state
// and PKCE cookies LoginHandler set) and hands the verified identity -
// subject and preferred username - to onIdentity, which owns everything
// app-specific from there: claiming the account during setup, or checking
// that this is the account's owner and creating a session.
//
// This is mounted as a raw net/http route rather than a huma operation,
// since an OAuth redirect callback isn't a JSON request/response - the
// same reasoning applies to LoginHandler.
func (c *Client) CallbackHandler(onIdentity func(w http.ResponseWriter, r *http.Request, subject, preferredUsername string)) http.HandlerFunc {
	return rp.CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, relyingParty rp.RelyingParty) {
		claims := tokens.IDTokenClaims
		onIdentity(w, r, claims.Subject, claims.PreferredUsername)
	}, c.rp)
}
