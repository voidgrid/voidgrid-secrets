package oidc

import "sync"

// Provider holds a deployment's OIDC client once configured: built once
// at startup if setup already chose OIDC, or installed directly right
// after a successful SetupOIDC call so login works immediately without a
// restart. Both the login-start/callback routes and the setup-completion
// handler share the same Provider.
type Provider struct {
	mu     sync.RWMutex
	client *Client
}

// Set installs c as the current client, replacing any previous one.
func (p *Provider) Set(c *Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.client = c
}

// Get returns the current client, or ok=false if none has been
// configured yet, or construction failed (e.g. the issuer was
// unreachable at startup). Callers must handle ok=false gracefully, not
// treat it as fatal: recovery-code login has to keep working even when
// the OIDC provider itself is unavailable.
func (p *Provider) Get() (c *Client, ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.client, p.client != nil
}
