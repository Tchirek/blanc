VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X github.com/Tchirek/blanc/internal/version.Version=$(VERSION) -X github.com/Tchirek/blanc/internal/version.Commit=$(COMMIT) -X github.com/Tchirek/blanc/internal/version.Date=$(DATE)
BINARY ?= dist/blanc

ifeq ($(OS),Windows_NT)
BINARY := dist/blanc.exe
endif

.PHONY: build test vet fmt clean web web-smoke dist

build:
	mkdir -p dist
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/blanc

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

web:
	VERSION=$(VERSION) COMMIT=$(COMMIT) sh scripts/build-web.sh dist/web

web-smoke: web
	node scripts/web-smoke.mjs dist/web testdata

dist:
	sh scripts/dist.sh $(VERSION)

clean:
	rm -rf dist
