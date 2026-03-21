PLUGIN_NAME := vault-plugin-secrets-honeycombio
PLUGIN_DIR := cmd/$(PLUGIN_NAME)

# Use mise to resolve Go if available, otherwise fall back to system Go.
MISE := $(shell command -v mise 2>/dev/null)
ifdef MISE
  GO := mise exec -- go
else
  GO := go
endif

.PHONY: build lint test testacc validate validate-down

build:
	$(GO) build -o bin/$(PLUGIN_NAME) ./$(PLUGIN_DIR)

lint:
ifdef MISE
	mise exec -- golangci-lint run
else
	golangci-lint run
endif

test:
	$(GO) test ./...

testacc:
	VAULT_ACC=1 $(GO) test ./... -v -run TestAcceptance

validate:
	docker compose up --build -d

validate-down:
	docker compose down
