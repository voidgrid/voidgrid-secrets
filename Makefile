VERSION ?= v0.1.0

.PHONY: build run vet test lint fmt lint-workflows live-test migrate docker-build dev

build:
	./scripts/build.sh

run: build
	./bin/voidgrid-secrets

vet:
	./scripts/vet.sh

test:
	./scripts/test.sh

lint:
	./scripts/lint.sh

fmt:
	./scripts/fmt.sh

lint-workflows:
	./scripts/actionlint.sh

live-test:
	./scripts/live-test.sh

migrate:
	@echo "migrations run automatically on server startup; no separate step needed"

docker-build:
	docker build -t voidgrid-secrets:$(VERSION) -t voidgrid-secrets:latest -f deploy/docker/Dockerfile .

dev:
	./scripts/dev.sh
