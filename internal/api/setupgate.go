package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
)

// SetupStatusChecker reports whether the first-run setup wizard has
// completed.
type SetupStatusChecker interface {
	IsComplete(ctx context.Context) (bool, error)
}

// alwaysAllowedOperations are reachable regardless of setup state.
var alwaysAllowedOperations = map[string]bool{
	"setup-status": true,
}

// onlyIncompleteOperations are reachable only while setup has not yet
// completed; once complete, they 409 rather than letting the wizard be
// re-run.
var onlyIncompleteOperations = map[string]bool{
	"setup-password-init":    true,
	"setup-password-confirm": true,
	"setup-oidc":             true,
}

// setupGateMiddleware locks the entire API behind the first-run setup
// wizard: every operation except setup-status and the setup-* operations
// themselves is unreachable (503) until setup completes, and the setup-*
// operations become unreachable (409) once it has, so the wizard can never
// be re-run against a live deployment.
func setupGateMiddleware(api huma.API, checker SetupStatusChecker) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		opID := ctx.Operation().OperationID

		if alwaysAllowedOperations[opID] {
			next(ctx)
			return
		}

		complete, err := checker.IsComplete(ctx.Context())
		if err != nil {
			_ = huma.WriteErr(api, ctx, 500, "internal error")
			return
		}

		if onlyIncompleteOperations[opID] {
			if complete {
				_ = huma.WriteErr(api, ctx, 409, "setup already completed")
				return
			}
			next(ctx)
			return
		}

		if !complete {
			_ = huma.WriteErr(api, ctx, 503, "setup wizard must be completed first")
			return
		}

		next(ctx)
	}
}
