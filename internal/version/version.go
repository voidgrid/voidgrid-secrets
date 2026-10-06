// Package version holds the build's version, stamped in at build time:
//
//	go build -ldflags "-X github.com/voidgrid/voidgrid-secrets/internal/version.Version=v1.2.3"
//
// The release workflow passes the git tag; local builds pass `git
// describe`. Anything built without it reports "dev".
package version

// Version is this build's version.
var Version = "dev"
