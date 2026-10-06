package session

import (
	"sync"
	"time"
)

// maxTrackedUsernames bounds the limiter's memory: past this many
// usernames with recent failures, expired entries are pruned, and if none
// have expired, new usernames aren't tracked until some do.
const maxTrackedUsernames = 10000

// AttemptLimiter refuses further login attempts for a username once it
// has had Max failures within Window, until that window has passed since
// the first of them. A success clears the count. It's keyed by username
// rather than client address because behind a reverse proxy every
// request comes from the proxy's address.
//
// The trade-off: anyone who knows a username can keep that account locked
// out of password and recovery-code login by failing on purpose. Sessions
// already open aren't affected, and OIDC sign-in doesn't go through it.
type AttemptLimiter struct {
	Max    int
	Window time.Duration
	// Now returns the current time; tests replace it.
	Now func() time.Time

	mu      sync.Mutex
	entries map[string]*attempts
}

type attempts struct {
	count int
	first time.Time
}

// NewAttemptLimiter returns a limiter allowing max failures per username
// within window.
func NewAttemptLimiter(maxFailures int, window time.Duration) *AttemptLimiter {
	return &AttemptLimiter{Max: maxFailures, Window: window, Now: time.Now, entries: map[string]*attempts{}}
}

// Allow reports whether username may attempt to log in now. A nil
// limiter allows everything.
func (l *AttemptLimiter) Allow(username string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[username]
	if !ok {
		return true
	}
	if l.Now().Sub(e.first) >= l.Window {
		delete(l.entries, username)
		return true
	}
	return e.count < l.Max
}

// Fail records a failed attempt for username.
func (l *AttemptLimiter) Fail(username string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	e, ok := l.entries[username]
	if ok && now.Sub(e.first) < l.Window {
		e.count++
		return
	}
	if !ok && len(l.entries) >= maxTrackedUsernames {
		for k, old := range l.entries {
			if now.Sub(old.first) >= l.Window {
				delete(l.entries, k)
			}
		}
		if len(l.entries) >= maxTrackedUsernames {
			return
		}
	}
	l.entries[username] = &attempts{count: 1, first: now}
}

// Succeed clears username's failure count.
func (l *AttemptLimiter) Succeed(username string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, username)
}
