# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.PHONY: help all build install lint vet vuln test check clean
help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Parent otfabric/go.work does not list this module; isolate toolchain commands.
export GOWORK := off

# Output directory for generated binaries
BIN_DIR := bin
PKGS := $(shell go list ./...)
# Library packages for coverage (exclude CLI)
TEST_PKGS := $(shell go list ./... | grep -v '/cmd/')

# Version info
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TAG := $(shell git describe --tags --exact-match 2>/dev/null || echo "")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y%m%d-%H:%M:%S)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.tag=$(TAG) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

all: build ## Default target: build otprobe binary

build: check ## Build otprobe binary
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/otprobe ./cmd/otprobe

install: build ## Install otprobe to /usr/local/bin (may require sudo)
	sudo install -m 0755 $(BIN_DIR)/otprobe /usr/local/bin/otprobe

fmt: ## Format Go code with gofmt
	@echo "Running gofmt"
	@gofmt -w .

lint: ## Run staticcheck
	@echo "Running staticcheck"
	@staticcheck $(PKGS)

lint-ci: ## Run golangci-lint
	@echo "Running golangci-lint"
	@golangci-lint run ./...

vet: ## Run go vet on project packages
	@echo "Running go vet on packages: $(PKGS)"
	@go vet $(PKGS)

vuln: ## Run govulncheck
	@echo "Running govulncheck"
	@govulncheck ./...

test: ## Run fast tests
	@echo "Running fast tests on packages: $(PKGS)"
	@go test $(PKGS)

test-race: ## Run tests with race detector (CI-like)
	@echo "Running race tests on packages: $(PKGS)"
	@go test -count=1 -timeout=120s -race $(PKGS)

coverage: ## Run tests with coverage on library packages (writes coverage.out)
	@echo "Running coverage on packages: $(TEST_PKGS)"
	@go test -count=1 -race -coverprofile=coverage.out -covermode=atomic $(TEST_PKGS)

cover: coverage ## Open coverage report in browser
	@echo "Opening coverage report"
	@go tool cover -html=coverage.out

check: fmt lint lint-ci vet vuln test test-race coverage ## Run lint + vet + vuln + test

clean: ## Remove generated binaries
	@rm -rf $(BIN_DIR)
