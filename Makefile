SHELL := /usr/bin/env bash

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)
GO_PACKAGES := ./cmd/... ./internal/...

.PHONY: all build build-go build-web test lint audit clean

all: lint test build

build: build-web build-go

build-web:
	cd web && npm run build:embedded

build-go:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/witshield-controller ./cmd/witshield-controller
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/witshield-agent ./cmd/witshield-agent
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/witshield-helper ./cmd/witshield-helper

test:
	go test -race -count=1 $(GO_PACKAGES)
	cd web && npm test

lint:
	test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './web/node_modules/*'))"
	go vet $(GO_PACKAGES)
	cd web && npm run lint && npm run typecheck
	bash -n scripts/*.sh scripts/tests/*.sh

audit:
	cd web && npm audit --audit-level=high
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 $(GO_PACKAGES)
	go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 $(GO_PACKAGES)
	scripts/run-gosec.sh $(GO_PACKAGES)

clean:
	@if [[ -d dist ]]; then find dist -mindepth 1 -maxdepth 1 -delete; fi
