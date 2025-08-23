# Makefile for TR-34 Key Import/Export

# Variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Binary names
IMPORT_BINARY=tr34-import
EXPORT_BINARY=tr34-export
TR31_IMPORT_BINARY=tr31-import
TR31_EXPORT_BINARY=tr31-export

# Build directories
BUILD_DIR=build
CMD_IMPORT=cmd/import
CMD_EXPORT=cmd/export

# Targets
.PHONY: all build clean test fmt vet deps help

all: clean deps fmt vet test build

build: build-import build-export build-tr31 build-tr31-export ## Build all binaries

build-import: ## Build the import binary
	@echo "Building import binary..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(IMPORT_BINARY) ./$(CMD_IMPORT)
	@echo "✓ Built $(BUILD_DIR)/$(IMPORT_BINARY)"

build-export: ## Build the export binary
	@echo "Building export binary..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(EXPORT_BINARY) ./$(CMD_EXPORT)
	@echo "✓ Built $(BUILD_DIR)/$(EXPORT_BINARY)"

build-tr31: ## Build the TR-31 import binary
	@echo "Building TR-31 import binary..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(TR31_IMPORT_BINARY) ./cmd/tr31-import
	@echo "✓ Built $(BUILD_DIR)/$(TR31_IMPORT_BINARY)"

build-tr31-export: ## Build the TR-31 export binary
	@echo "Building TR-31 export binary..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(TR31_EXPORT_BINARY) ./cmd/tr31-export
	@echo "✓ Built $(BUILD_DIR)/$(TR31_EXPORT_BINARY)"


clean: ## Remove build artifacts
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned"

test: ## Run tests
	@echo "Running tests..."
	$(GOTEST) -v ./...

fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) ./...
	@echo "✓ Formatted"

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...
	@echo "✓ Vetted"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✓ Dependencies ready"

install: build ## Install binaries to GOPATH/bin
	@echo "Installing binaries..."
	@cp $(BUILD_DIR)/$(IMPORT_BINARY) $(GOPATH)/bin/
	@cp $(BUILD_DIR)/$(EXPORT_BINARY) $(GOPATH)/bin/
	@cp $(BUILD_DIR)/$(TR31_IMPORT_BINARY) $(GOPATH)/bin/
	@cp $(BUILD_DIR)/$(TR31_EXPORT_BINARY) $(GOPATH)/bin/
	@echo "✓ Installed to $(GOPATH)/bin/"

help: ## Show this help message
	@echo "TR-34 Key Import/Export - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Usage: make [target]"
	@echo "Example: make build"

# Default target
.DEFAULT_GOAL := help