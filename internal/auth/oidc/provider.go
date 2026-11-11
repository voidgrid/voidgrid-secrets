package oidc

import (
	"context"
	"log"
	"sync"
	"time"
)

// loadRetryInterval is the least time between attempts to build the
// client. /login/oidc needs no sign-in, so without it anyone could make
// the server call an unreachable issuer on every request.
const loadRetryInterval = 15 * time.Second

// Provider holds a deployment's OIDC client once configured: installed
// directly right after a successful SetupOIDC call, or built by Load from
// the saved config. Both the login-start/callback routes and the
// setup-completion handler share the same Provider.
type Provider struct {
	// Load builds the client from the saved config, returning nil with no
	// error when OIDC isn't configured. While there is no client, Get
	// calls it again (at most once per loadRetryInterval), so an issuer
	// that was unreachable when the server started is picked up on a later
	// sign-in instead of needing a restart. nil means Set is the only way
	// in.
	Load func(ctx context.Context) (*Client, error)

	mu       sync.Mutex
	client   *Client
	lastLoad time.Time
}

// Set installs c as the current client, replacing any previous one.
func (p *Provider) Set(c *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.client = c
}

// Get returns the current client, trying Load first if there is none. It
// returns ok=false if OIDC isn't configured or the issuer can't be
// reached. Callers must handle ok=false gracefully, not treat it as
// fatal: recovery has to keep working even when the OIDC provider itself
// is unavailable.
func (p *Provider) Get() (c *Client, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == nil && p.Load != nil && time.Since(p.lastLoad) >= loadRetryInterval {
		p.lastLoad = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client, err := p.Load(ctx)
		if err != nil {
			log.Printf("oidc: provider unavailable, will retry on a later sign-in: %v", err)
		}
		p.client = client
	}
	return p.client, p.client != nil
}
