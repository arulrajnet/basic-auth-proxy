# Basic Auth Proxy Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOLINT=golangci-lint

# Binary name
BINARY_NAME=basic-auth-proxy
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Main package path
MAIN_PACKAGE=.

# All packages
PACKAGES=$(shell go list ./... | grep -v /vendor/)

# Build directory
BUILD_DIR=build
DIST_DIR=dist

# Build tags
BUILD_TAGS=

# Flags for the go linker
LDFLAGS=-ldflags "-X github.com/arulrajnet/basic-auth-proxy/pkg/version.VERSION=$(VERSION) -extldflags '-static'"

.PHONY: all build clean test lint fmt vet tidy help run docker

all: clean lint test build

# Build the application
build: clean
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Build complete!"

# Build for multiple platforms
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)
	@echo "Multi-platform build complete!"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	$(GOCLEAN)
	@echo "Clean complete!"

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v $(PACKAGES)
	@echo "Tests complete!"

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -coverprofile=$(BUILD_DIR)/coverage.out $(PACKAGES)
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report generated at $(BUILD_DIR)/coverage.html"

# Run linter
lint:
	@echo "Running linter..."
	@if ! command -v $(GOLINT) &> /dev/null; then \
			echo "golangci-lint not found, installing..."; \
			curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
	fi
	$(GOLINT) run --timeout=5m
	@echo "Lint complete!"

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt $(PACKAGES)
	@echo "Format complete!"

# Verify code
vet:
	@echo "Vetting code..."
	$(GOCMD) vet $(PACKAGES)
	@echo "Vet complete!"

# Update dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy
	@echo "Tidy complete!"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	@echo "Dependencies installed!"

# Run the application
run: build
	@echo "Running $(BINARY_NAME)..."
	@$(BUILD_DIR)/$(BINARY_NAME)

# Generate a list of all Go files
list-go-files:
	@echo "Listing all Go files..."
	@find . -name "*.go" | grep -v "/vendor/" | sort

# Show help
help:
	@echo "Available targets:"
	@echo "  all            - Clean, lint, test, and build"
	@echo "  build          - Build the application"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  vet            - Verify code"
	@echo "  tidy           - Update dependencies"
	@echo "  deps           - Install dependencies"
	@echo "  run            - Run the application"
	@echo "  list-go-files  - List all Go files"
	@echo "  help           - Show this help"

# Default target
.DEFAULT_GOAL := help
