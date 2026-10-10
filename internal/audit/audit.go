// Package audit defines what gets recorded in the audit log: who did what
// to which resource, plus details and where the request came from. Storage
// (storage.AuditRepo) writes events; this package only describes them, so
// any layer - login, setup, HTTP handlers - can record one without
// depending on storage.
package audit

import (
	"context"
	"log"
	"net"
	"net/http"
)

// Actor types.
const (
	ActorUser  = "user"
	ActorToken = "token"
	// ActorAnonymous is a request that hasn't authenticated as anyone:
	// failed logins, setup attempts, rejected machine tokens.
	ActorAnonymous = "anonymous"
	// ActorSystem is the server itself, or the break-glass command run
	// inside its container.
	ActorSystem = "system"
)

// Actions. Everything that reveals a value or changes something is
// recorded, along with failed and refused attempts.
const (
	Login           = "login"
	LoginFailed     = "login_failed"
	LoginLockedOut  = "login_locked_out"
	Logout          = "logout"
	TokenAuthFailed = "token_auth_failed" //nolint:gosec // an action name, not a credential

	SetupTokenRejected  = "setup_token_rejected" //nolint:gosec // an action name, not a credential
	SetupAccountCreated = "setup_account_created"
	SetupCompleted      = "setup_completed"

	RecoveryStarted   = "recovery_started"
	RecoveryFailed    = "recovery_failed"
	RecoveryCompleted = "recovery_completed"
	BreakGlassIssued  = "break_glass_issued"

	SecretCreate = "secret_create"
	SecretUpdate = "secret_update"
	SecretRename = "secret_rename"
	SecretDelete = "secret_delete"
	SecretReveal = "reveal"
	AccessDenied = "access_denied"

	TokenCreate    = "token_create"
	TokenRevoke    = "token_revoke"
	TokenGrant     = "token_grant"
	TokenUngrant   = "token_ungrant"
	TokenGrantsSet = "token_grants_set"

	GroupCreate  = "group_create"
	GroupRename  = "group_rename"
	GroupDelete  = "group_delete"
	GroupMembers = "group_members"

	AuditPruned = "audit_pruned"
)

// Actor is who performed an action. ID is 0 for anonymous and system.
type Actor struct {
	Type string
	ID   int64
}

// User returns a user actor.
func User(id int64) Actor { return Actor{Type: ActorUser, ID: id} }

// Token returns a machine-token actor.
func Token(id int64) Actor { return Actor{Type: ActorToken, ID: id} }

// Anonymous returns the actor for unauthenticated requests.
func Anonymous() Actor { return Actor{Type: ActorAnonymous} }

// System returns the actor for the server's own actions.
func System() Actor { return Actor{Type: ActorSystem} }

// Event is one audit log entry. ResourceID 0 means none. Details never
// hold secret values, passwords, tokens or codes.
type Event struct {
	Actor        Actor
	Action       string
	ResourceType string
	ResourceID   int64
	Details      map[string]string
}

// Logger writes events.
type Logger interface {
	Log(ctx context.Context, e Event) error
}

// Record writes e, for actions that have already happened: a failure to
// record is logged to stderr rather than failing the request. Reveals,
// which must not happen unrecorded, call Logger.Log directly and fail if
// it does. A nil logger records nothing.
func Record(ctx context.Context, l Logger, e Event) {
	if l == nil {
		return
	}
	if err := l.Log(ctx, e); err != nil {
		log.Printf("audit: failed to record %s: %v", e.Action, err)
	}
}

type requestKey struct{}

// RequestInfo is where a request came from, attached to every event
// recorded while handling it.
type RequestInfo struct {
	// IP is the connecting address - behind a reverse proxy, the proxy's.
	IP string
	// ForwardedFor is the X-Forwarded-For header as received. It's set by
	// the proxy (or by the client, if there is none), so it's recorded
	// as-is and not trusted for anything.
	ForwardedFor string
	UserAgent    string
}

// Middleware attaches the request's RequestInfo to its context.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		info := RequestInfo{
			IP:           ip,
			ForwardedFor: truncate(r.Header.Get("X-Forwarded-For"), 200),
			UserAgent:    truncate(r.UserAgent(), 200),
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestKey{}, info)))
	})
}

// RequestFrom returns the RequestInfo Middleware attached, if any.
func RequestFrom(ctx context.Context) (RequestInfo, bool) {
	info, ok := ctx.Value(requestKey{}).(RequestInfo)
	return info, ok
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
