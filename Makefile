.PHONY: build test lint lint-fix lint-verbose security check install clean vendor man all help

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Default target
all: build

# Build the binary
build:
	go build $(LDFLAGS) -o envctl ./cmd/envctl

# Build with race detector
build-race:
	go build -race $(LDFLAGS) -o envctl ./cmd/envctl

# Run tests
test:
	go test -race -cover ./...

# Run tests with verbose output
test-v:
	go test -race -cover -v ./...

# Run linter
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Lint with auto-fix where possible
lint-fix:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --fix; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Verbose lint output
lint-verbose:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run -v; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Run security checks
security:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Run: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi

# Run all checks
check: lint security test

# Format code
fmt:
	go fmt ./...
	@if command -v gofumpt >/dev/null 2>&1; then \
		gofumpt -w .; \
	fi

# Tidy dependencies
tidy:
	go mod tidy

# Vendor dependencies
vendor:
	go mod vendor

# Install locally
install: build
	install -m 755 envctl /usr/local/bin/

# Install man pages (if generated)
install-man:
	@if [ -d "man" ]; then \
		install -d /usr/local/share/man/man1; \
		install -m 644 man/*.1 /usr/local/share/man/man1/; \
	fi

# Uninstall
uninstall:
	rm -f /usr/local/bin/envctl
	rm -f /usr/local/share/man/man1/envctl*.1

# Clean build artifacts
clean:
	rm -rf dist/ envctl envctl.exe
	go clean

# Build for all platforms
build-all:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		go build $(LDFLAGS) \
		-o dist/envctl-$${platform%/*}-$${platform#*/}$$([ $${platform%/*} = windows ] && echo .exe) ./cmd/envctl; \
		echo "Built: dist/envctl-$${platform%/*}-$${platform#*/}"; \
	done

# Generate man pages (requires cobra-doc)
man:
	@mkdir -p man
	go run ./tools/gendocs

# Development: run daemon
dev-daemon:
	go run ./cmd/envctl daemon run

# Development: watch and rebuild
dev:
	@if command -v air >/dev/null 2>&1; then \
		air; \
	else \
		echo "air not installed. Run: go install github.com/cosmtrek/air@latest"; \
		echo "Or just run: make build"; \
	fi

# Show version
version:
	@echo $(VERSION)

# Show help
help:
	@echo "envctl Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build      - Build the binary"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linter"
	@echo "  make lint-fix   - Run linter with auto-fix"
	@echo "  make security   - Run security checks"
	@echo "  make check      - Run all checks (lint, security, test)"
	@echo "  make install    - Install to /usr/local/bin"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make build-all  - Build for all platforms"
	@echo "  make vendor     - Vendor dependencies"
	@echo "  make fmt        - Format code"
	@echo "  make help       - Show this help"
