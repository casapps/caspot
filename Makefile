# Variables
VERSION ?= 1.0.0
BINARY_NAME = caspot
BUILD_DIR = build
CGO_ENABLED = 0
LDFLAGS = -ldflags '-extldflags "-static" -s -w -X main.version=$(VERSION) -X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'

# Default target
.DEFAULT_GOAL := build

# Build for all platforms
build: clean
	@echo "Building $(BINARY_NAME) v$(VERSION) for all platforms..."
	@mkdir -p $(BUILD_DIR)

	# Linux AMD64
	@echo "Building for Linux AMD64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/caspot

	# Linux ARM64
	@echo "Building for Linux ARM64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/caspot

	# Windows AMD64
	@echo "Building for Windows AMD64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/caspot

	# macOS AMD64
	@echo "Building for macOS AMD64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/caspot

	# macOS ARM64 (Apple Silicon)
	@echo "Building for macOS ARM64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/caspot

	# Host binary
	@echo "Building host binary..."
	@CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/caspot

	@echo "Build complete. Binaries available in $(BUILD_DIR)/"

# Build only host binary
build-host:
	@echo "Building host binary..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/caspot
	@echo "Binary available at $(BUILD_DIR)/$(BINARY_NAME)"

# Release to GitHub
release: build
	@echo "Creating checksums..."
	@cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)-* > checksums.txt
	@echo "Release artifacts ready in $(BUILD_DIR)/"
	@echo "Upload to GitHub releases manually or use 'gh release create v$(VERSION) $(BUILD_DIR)/*'"

# Docker build and push
docker:
	@echo "Building Docker image..."
	@docker build -t ghcr.io/casapps/$(BINARY_NAME):$(VERSION) .
	@docker build -t ghcr.io/casapps/$(BINARY_NAME):latest .
	@echo "Pushing to registry..."
	@docker push ghcr.io/casapps/$(BINARY_NAME):$(VERSION)
	@docker push ghcr.io/casapps/$(BINARY_NAME):latest

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Test coverage report: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html

# Development server
dev:
	@echo "Starting development server..."
	@go run ./cmd/caspot --dev

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod verify

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .

# Lint code
lint:
	@echo "Running linters..."
	@golangci-lint run

# Generate documentation
docs:
	@echo "Generating documentation..."
	@godoc -http=:6060
	@echo "Documentation server running at http://localhost:6060"

# Install locally
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Installation complete. Run '$(BINARY_NAME)' to start."

# Uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstallation complete."

# Help
help:
	@echo "Available targets:"
	@echo "  build       - Build binaries for all platforms"
	@echo "  build-host  - Build binary for current host only"
	@echo "  release     - Prepare release artifacts"
	@echo "  docker      - Build and push Docker image"
	@echo "  test        - Run tests with coverage"
	@echo "  clean       - Clean build artifacts"
	@echo "  dev         - Start development server"
	@echo "  deps        - Install dependencies"
	@echo "  fmt         - Format code"
	@echo "  lint        - Run linters"
	@echo "  docs        - Generate documentation"
	@echo "  install     - Install locally"
	@echo "  uninstall   - Uninstall"
	@echo "  help        - Show this help"

.PHONY: build build-host release docker test clean dev deps fmt lint docs install uninstall help