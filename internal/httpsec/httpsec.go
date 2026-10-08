// Package httpsec decides, per request, whether the server may issue
// cookies without the Secure attribute. Sign-in cookies are Secure, which
// browsers refuse to keep over plain HTTP, so sign-in over http://LAN-IP
// fails silently. The operator can list networks (home LAN, Tailscale)
// whose plain-HTTP sign-ins are allowed; everyone else must use HTTPS.
package httpsec

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseNets parses a comma-separated list of CIDRs. Empty input yields no
// networks, which keeps Secure on for every request.
func ParseNets(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q (want CIDR like 192.168.1.0/24): %w", part, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Middleware returns middleware enforcing the policy. On plain HTTP from a
// listed network it strips Secure from every cookie the response sets; on
// plain HTTP from anywhere else it refuses the sign-in routes with a
// message. HTTPS (direct, or X-Forwarded-Proto: https) is left untouched.
// The peer is the TCP peer address; X-Forwarded-For is never trusted, as
// a spoofed header could otherwise switch Secure off.
func Middleware(nets []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isHTTPS(r) {
				next.ServeHTTP(w, r)
				return
			}
			if peerAllowed(r, nets) {
				next.ServeHTTP(&insecureCookies{ResponseWriter: w}, r)
				return
			}
			if isSignInPath(r.URL.Path) {
				http.Error(w, "Sign-in over plain HTTP is not allowed from this address. Use HTTPS, or ask the operator to list your network in VOIDGRID_HTTP_ALLOWED_NETS.", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func peerAllowed(r *http.Request, nets []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	for _, p := range nets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// isSignInPath reports whether a route issues or completes a sign-in:
// the login, recovery and setup flows, in the web UI and the API. Bearer
// token routes are not listed; they set no cookies.
func isSignInPath(p string) bool {
	if p == "/api/v1/setup/status" { // read-only, sets no cookie
		return false
	}
	for _, prefix := range []string{"/login", "/recover", "/setup", "/api/v1/auth/login", "/api/v1/recover", "/api/v1/setup"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// insecureCookies removes the Secure attribute from Set-Cookie headers as
// the response starts.
type insecureCookies struct {
	http.ResponseWriter
	done bool
}

func (w *insecureCookies) strip() {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	cookies := h.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, c := range cookies {
		h.Add("Set-Cookie", stripSecure(c))
	}
}

func stripSecure(cookie string) string {
	parts := strings.Split(cookie, ";")
	kept := parts[:1]
	for _, p := range parts[1:] {
		if strings.EqualFold(strings.TrimSpace(p), "secure") {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, ";")
}

func (w *insecureCookies) WriteHeader(code int) {
	w.strip()
	w.ResponseWriter.WriteHeader(code)
}

func (w *insecureCookies) Write(b []byte) (int, error) {
	w.strip()
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *insecureCookies) Unwrap() http.ResponseWriter { return w.ResponseWriter }
