# syntax=docker/dockerfile:1

# Builds the voidgrid-secrets binary into a small image. The database is a
# single SQLite file (/data/voidgrid.db) opened by the app itself, so the
# app is the only process: no supervisor, no separate database server.
# alpine (not distroless) keeps a shell and wget for the healthcheck and for
# operators who exec in, and the sqlite3 command-line tool for looking
# inside the database (read-only, see docs/deployment.md).

# The test toolchain, shared by the image build below and by
# scripts/test.sh (`make test`, which builds just this stage and runs the
# tests in it), so the two can't drift apart. gcc/musl-dev are needed only
# for `-race` (cgo); the SQLite driver is pure Go.
FROM golang:1.26-alpine AS testenv
RUN apk add --no-cache gcc musl-dev

# Tests gate the image: a failing `go vet`/`go test` here fails the whole
# build, before `go build` ever runs. The shipped binary still builds with
# CGO_ENABLED=0, so the cgo toolchain doesn't affect its portability.
FROM testenv AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./...
RUN go test -race ./...
# VERSION is stamped into the binary (internal/version); the release
# workflow passes the git tag.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/voidgrid/voidgrid-secrets/internal/version.Version=${VERSION}" \
    -o /out/voidgrid-secrets ./cmd/voidgrid-secrets

FROM alpine:3.20
RUN apk add --no-cache ca-certificates sqlite
COPY --from=builder /out/voidgrid-secrets /usr/local/bin/voidgrid-secrets

# Nothing here needs root, so the container runs as UID/GID 1000. /data,
# /run/secrets and /export are created and owned by 1000 here so fresh
# named volumes mounted there inherit that ownership. /export is where a
# one-shot compose service copies this binary for other containers to use
# `voidgrid-secrets run` from.
RUN addgroup -g 1000 voidgrid && \
    adduser -D -H -u 1000 -G voidgrid voidgrid && \
    mkdir -p /data /run/secrets /export && \
    chown -R 1000:1000 /data /run/secrets /export
USER 1000:1000

ENV VOIDGRID_LISTEN_ADDR=0.0.0.0:8780 \
    VOIDGRID_ROOT_KEY_PATH=/run/secrets/voidgrid-root-key \
    VOIDGRID_DB_PATH=/data/voidgrid.db

VOLUME ["/data"]
EXPOSE 8780

# The status route needs no auth and is exempt from the plain-HTTP sign-in
# policy; it answers once the database is open and migrated.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8780/api/v1/setup/status || exit 1

ENTRYPOINT ["/usr/local/bin/voidgrid-secrets"]
