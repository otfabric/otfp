# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.PHONY: help all build install lint vet test check clean
help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Output directory for generated binaries
BIN_DIR := bin
PKGS := $(shell go list ./...)

# Version info
VERSION := $(shell cat cmd/otprobe/version.txt)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
REVISION := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_USER := $(shell whoami)
BUILD_DATE := $(shell date -u +%Y%m%d-%H:%M:%S)
LDFLAGS := -X main.Version=$(VERSION) -X main.Branch=$(BRANCH) -X main.Revision=$(REVISION) -X main.BuildUser=$(BUILD_USER) -X main.BuildDate=$(BUILD_DATE)

all: build ## Default target: build otprobe binary

build: check ## Build otprobe binary
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/otprobe ./cmd/otprobe

install: build ## Install otprobe to /usr/local/bin (may require sudo)
	sudo install -m 0755 $(BIN_DIR)/otprobe /usr/local/bin/otprobe

lint: ## Run linter (golangci-lint preferred, fallback golint)
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	elif command -v golint >/dev/null 2>&1; then \
		golint $(PKGS); \
	else \
		echo "No Go linter found. Install golangci-lint or golint."; \
		exit 1; \
	fi

vet: ## Run go vet on project packages
	@echo "Running go vet on packages: $(PKGS)"
	@go vet $(PKGS)

test: ## Run fast tests
	@echo "Running fast tests on packages: $(PKGS)"
	@go test $(PKGS)

test-race: ## Run tests with race detector (CI-like)
	@echo "Running race tests on packages: $(PKGS)"
	@go test -count=1 -timeout=120s -race $(PKGS)

check: lint vet test test-race ## Run lint + vet + test

clean: ## Remove generated binaries
	@rm -rf $(BIN_DIR)
