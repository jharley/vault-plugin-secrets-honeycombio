# Agent Guidelines

## Project

HashiCorp Vault secrets engine plugin for Honeycomb.io. Generates and manages dynamic Configuration Keys and Ingest Keys.

## Environment

- **Go version:** 1.26.1 (pinned via `.go-version`, managed by mise)
- Use the Makefile for all build/test/lint commands — it handles mise activation automatically if needed.
- **Docker:** `make validate` / `make validate-down` to run Vault + OpenBao with the plugin loaded.

## Testing

- **Framework:** All Go tests MUST use [testify](https://github.com/stretchr/testify) (`assert` and `require` packages).
  - Use `require` for preconditions that should stop the test on failure (e.g., setup errors, nil checks).
  - Use `assert` for the actual test assertions where you want all failures reported.
  - Do NOT use `require` inside HTTP handler functions in tests (causes `testifylint` failure).
- **TDD:** Write tests first, verify they fail, then implement.
- **Run tests:** `make test`
- **Lint:** `make lint`
- **Build:** `make build`
- **Acceptance tests:** `make testacc` (requires `HONEYCOMB_KEY_ID`, `HONEYCOMB_KEY_SECRET`, `HONEYCOMB_ENVIRONMENT` env vars)
- Test helpers (`newTestBackend`, `newTestClient`) register cleanup via `t.Cleanup` — callers should NOT call `defer srv.Close()`.

## Code Style

- Standard Go conventions. All code must pass `make lint` cleanly before committing.
- Internal packages live under `internal/`.
- A minimal Honeycomb API client lives in `internal/client/`.
- Vault SDK `FieldData.Get()` type assertions are idiomatic and should use `//nolint:forcetypeassert`. When multiple assertions are grouped, add a single explanatory comment above the block.
- `context.Context` should be created at the entry point (test function, handler, `main`) and propagated through all calls. Never call `context.Background()` deep in a call chain — accept a `ctx` parameter instead.

## Honeycomb API

- Honeycomb API OpenAPI spec: `https://api.honeycomb.io/api.yaml`
- The `api-keys:write` scope implies read — the API never returns both `api-keys:read` and `api-keys:write`.
- Ingest keys only support the `create_datasets` permission. The API rejects requests that include configuration-only permissions for ingest keys — use `omitempty` on config-only permission fields.
- The `Ratelimit` response header uses the format `limit=X, remaining=Y, reset=Z` (IETF draft-07).
