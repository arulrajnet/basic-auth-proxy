# Variables
GO_BUILD=go build
OUTPUT_DIR=./dist
GOLANGCILINT=golangci-lint
BINERY=basic-auth-proxy


# Targets
.PHONY: all
all: build

.PHONY: run
run: build
	$(OUTPUT_DIR)/$(BINERY) -config=./config.yaml

.PHONY: build
build: clean build_linux_amd64 build_linux_arm build_windows_amd64

.PHONY: build_binary
build_binary: clean $(BINERY)

.PHONY: lint
lint:
	$(GOLANGCILINT) run

# Build for given platform. The arch and os set outside of the makefile
.PHONY: $(BINERY)
$(BINERY): clean
	CGO_ENABLED=0 $(GO_BUILD) -a -installsuffix cgo -ldflags="-X github.com/arulrajnet/basic-auth-proxy/pkg/version.VERSION=${VERSION}" -o $(OUTPUT_DIR)/$(BINERY) ./cmd/

# Build for different platforms
.PHONY: build_linux_amd64
build_linux_amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO_BUILD) -a -installsuffix cgo -ldflags="-X github.com/arulrajnet/basic-auth-proxy/pkg/version.VERSION=${VERSION}" -o $(OUTPUT_DIR)/$(BINERY)_amd64 ./cmd/

.PHONY: build_linux_arm
build_linux_arm:
	GOOS=linux GOARCH=arm CGO_ENABLED=0 $(GO_BUILD) -a -installsuffix cgo -ldflags="-X github.com/arulrajnet/basic-auth-proxy/pkg/version.VERSION=${VERSION}" -o $(OUTPUT_DIR)/$(BINERY)_arm ./cmd/

.PHONY: build_windows_amd64
build_windows_amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO_BUILD) -a -installsuffix cgo -ldflags="-X github.com/arulrajnet/basic-auth-proxy/pkg/version.VERSION=${VERSION}" -o $(OUTPUT_DIR)/$(BINERY)_windows.exe ./cmd/

# Clean up binaries
.PHONY: clean
clean:
	rm -rf $(OUTPUT_DIR)/*
