# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.1 (2026-03-21)

### Bug Fixes

- handle pagination in ListEnvironments (#4)

### Improvements

- add Dependabot config for Go modules and GitHub Actions (#3)
- add PR labeling, title linting, and release note generation (#5)
- add CODEOWNERS, SECURITY.md, and CONTRIBUTING.md (#7)

### Dependencies

- bump actions/github-script from 7.0.1 to 8.0.0 (#6)

## 0.1.0 (2026-03-21)

Initial public release.

### Features

- Dynamic generation of Honeycomb.io **Configuration Keys** and **Ingest Keys**
- Automatic key revocation on lease expiry
- Lease renewal support
- Role-based access control with per-role key type, environment, and permissions
- WAL-based crash recovery for orphaned keys
- Honeycomb Management API credential validation on configuration
- Environment slug-to-ID resolution with TTL-based caching
- Compatible with both [HashiCorp Vault](https://www.vaultproject.io) and [OpenBao](https://openbao.org)
