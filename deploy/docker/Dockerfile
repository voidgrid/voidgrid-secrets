# syntax=docker/dockerfile:1

# Builds the voidgrid-secrets binary, rqlite (single-node, per the
# project's architecture decision), and s6-overlay into one container
# image. alpine (not distroless) is the base: s6-overlay needs a shell to
# run its service scripts, which distroless images don't have.

# rqlite ships a musl-linked binary release, matching alpine's musl libc,
# so no build-from-source step is needed here - just fetch and extract it.
# Declared before `builder` because the builder stage also needs this
# binary on PATH, to run the real-rqlited integration tests.
FROM alpine:3.20 AS rqlite
ARG RQLITE_VERSION=10.5.0
ADD https://github.com/rqlite/rqlite/releases/download/v${RQLITE_VERSION}/rqlite-v${RQLITE_VERSION}-linux-amd64-musl.tar.gz /tmp/rqlite.tar.gz
RUN mkdir -p /out /tmp/rqlite && \
    tar -xzf /tmp/rqlite.tar.gz -C /tmp/rqlite --strip-components=1 && \
    cp /tmp/rqlite/rqlited /out/rqlited

# The test toolchain, shared by the image build below and by
# scripts/test.sh (`make test`, which builds just this stage and runs the
# tests in it), so the two can't drift apart. gcc/musl-dev are needed only
# for `-race` (cgo). rqlited comes from the `rqlite` stage above so the
# integration tests (which skip themselves via exec.LookPath if it's
# missing) actually run.
FROM golang:1.26-alpine AS testenv
RUN apk add --no-cache gcc musl-dev
COPY --from=rqlite /out/rqlited /usr/local/bin/rqlited

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

# x86_64 only for now: the rqlite and s6-overlay asset names below are
# architecture-specific (e.g. "linux-amd64", "x86_64"). Extending this to
# arm64 (Raspberry Pi etc.) means swapping those names based on
# $TARGETARCH via buildx - not done here to keep this pass's scope to a
# single, well-tested platform.
FROM alpine:3.20
ARG S6_OVERLAY_VERSION=3.2.3.2

# xz is only needed to extract the s6-overlay tarballs below; drop it
# again immediately so it doesn't linger in the final image.
RUN apk add --no-cache xz ca-certificates && \
    wget -qO /tmp/s6-overlay-noarch.tar.xz "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" && \
    wget -qO /tmp/s6-overlay-x86_64.tar.xz "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz" && \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz && \
    tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz && \
    rm -rf /tmp/s6-overlay-*.tar.xz && \
    apk del xz

COPY --from=rqlite /out/rqlited /usr/local/bin/rqlited
COPY --from=builder /out/voidgrid-secrets /usr/local/bin/voidgrid-secrets
COPY deploy/docker/rootfs/ /

# Nothing here needs root, so the whole container - s6-overlay included -
# runs as UID/GID 1000. s6-overlay can run unprivileged as long as /run is
# writable by that user. /data, /run/secrets and /export are created and
# owned by 1000 here so fresh named volumes mounted there inherit that
# ownership. /export is where a one-shot compose service copies this
# binary for other containers to use `voidgrid-secrets run` from.
RUN addgroup -g 1000 voidgrid && \
    adduser -D -H -u 1000 -G voidgrid voidgrid && \
    mkdir -p /data/rqlite /run/secrets /export && \
    chown -R 1000:1000 /data /run /export
USER 1000:1000

ENV VOIDGRID_RQLITE_ADDR=http://127.0.0.1:4001 \
    VOIDGRID_LISTEN_ADDR=0.0.0.0:8443 \
    VOIDGRID_ROOT_KEY_PATH=/run/secrets/voidgrid-root-key \
    RQLITE_DATA_DIR=/data/rqlite

VOLUME ["/data"]
EXPOSE 8443

ENTRYPOINT ["/init"]
