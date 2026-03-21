# Contributing

Thank you for your interest in contributing to vault-plugin-secrets-honeycombio!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Copy `.envrc.example` to `.envrc`, fill in your Honeycomb credentials, and run `direnv allow`
4. Run `make test` to verify everything works

### Honeycomb Credentials

Running acceptance tests and the Docker validation environment requires a [Honeycomb Management Key](https://docs.honeycomb.io/configure/teams/manage-api-keys/) with `api-keys:write` scope. 
The key ID and secret are configured via the `HONEYCOMB_KEY_ID` and `HONEYCOMB_KEY_SECRET` environment variables.
You'll also need `HONEYCOMB_ENVIRONMENT` set to the slug of an environment to test against.

### Requirements

- Go 1.26 (version in `.go-version`)
- [golangci-lint](https://golangci-lint.run)
- [Docker](https://www.docker.com) (optional, for the validation environment)

## Development Workflow

```sh
make build     # compile the plugin
make test      # run tests with race detection
make lint      # run golangci-lint
make testacc   # run acceptance tests (requires Honeycomb credentials)
make validate  # start Vault + OpenBao with the plugin loaded
```

Agents see [AGENTS.md](AGENTS.md) for detailed code conventions and project guidelines.

## Pull Requests

- **Branch from `main`** and open a PR back to `main`
- **Use conventional commit prefixes** in your PR title — this is enforced by CI:
  - `feat:` — new functionality
  - `fix:` — bug fixes
  - `refactor:` / `perf:` / `chore:` / `docs:` / `ci:` / `test:` — improvements
  - `deps:` — dependency updates
  - `rel:` — release preparation (excluded from changelog)
  - Append `!` for breaking changes (e.g., `feat!:`)
- **All CI checks must pass** before merging: build, lint, test, acceptance, and PR title validation
- **Keep changes focused** — one concern per PR

## Reporting Issues

- **Bugs**: Open an issue with steps to reproduce
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) — do not open a public issue

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
