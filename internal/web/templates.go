// Package web serves the terminal-themed, server-rendered HTML UI: the
// setup wizard, login, the secrets browser, sharing management, and admin
// screens for users/groups/machine tokens.
//
// Plain html/template + forms were chosen over a JS framework or even
// htmx, per the project's simplicity priority: one language/toolchain, no separate frontend build, and a secrets
// manager's UI doesn't need heavy client-side interactivity.
package web

import (
	"html/template"
	"net/http"

	"github.com/voidgrid/voidgrid-secrets/internal/model"
	webassets "github.com/voidgrid/voidgrid-secrets/web"
)

// basePage carries the fields every page template can rely on: the
// logged-in user (nil if anonymous, e.g. on /login) and an optional
// flash error shown at the top of the page.
type basePage struct {
	User  *model.User
	Error string
	// RefreshTo, when set, makes the page immediately refresh to that
	// path (see continueSignIn for why that's sometimes needed instead
	// of a redirect).
	RefreshTo string
}

var pages = map[string]*template.Template{}

func init() {
	for _, name := range []string{
		"setup_init", "setup_confirm", "setup_oidc", "setup_oidc_done",
		"recovery_codes", "login", "login_recovery", "signin_continue",
		"secrets_list", "secret_new", "secret_detail", "secret_reveal",
		"users", "groups", "group_detail", "tokens", "token_detail",
	} {
		pages[name] = template.Must(template.New("layout").ParseFS(
			webassets.FS, "templates/layout.html", "templates/"+name+".html",
		))
	}
}

// render executes the named page template (see the list in init above)
// into w. data must be (or embed) basePage.
func render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Every page of a secrets manager can carry something sensitive (TOTP
	// secrets, recovery codes, revealed values, fresh machine tokens), so
	// none of them may land in a browser or proxy cache.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pages[name].ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}
