VERSION ?= 0.1.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X github.com/blanc-sh/blanc/internal/version.Version=$(VERSION) -X github.com/blanc-sh/blanc/internal/version.Commit=$(COMMIT) -X github.com/blanc-sh/blanc/internal/version.Date=$(DATE)

.PHONY: build test vet fmt clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/blanc ./cmd/blanc

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

clean:
	rm -rf dist
