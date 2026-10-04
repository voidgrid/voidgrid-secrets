// Package webassets embeds the project's HTML templates and static assets
// (CSS) so internal/web can serve them without relying on a file path
// that only exists at the repo root during development.
package webassets

import "embed"

//go:embed templates static
var FS embed.FS
