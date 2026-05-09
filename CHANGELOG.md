# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (2026-05-09)

### Improvements

- cache syft during release workflow (#22)
- improve Claude configuration (#32)

### Dependencies

- bump actions/github-script from 8.0.0 to 9.0.0 (#23)
- bump github.com/hashicorp/vault/sdk from 0.25.0 to 0.25.1 in the hashicorp group across 1 directory (#24)
- bump Go from 1.26.1 to 1.26.2 (#25)
- bump github.com/jackc/pgx/v5 from 5.9.1 to 5.9.2 (#26)
- bump goreleaser/goreleaser-action from 7.0.0 to 7.1.0 (#27)
- bump openbao/openbao from `6c75c97` to `fdc6da2` (#28)
- bump goreleaser/goreleaser-action from 7.1.0 to 7.2.1 (#29)
- bump Go from 1.26.2 to 1.26.3 (#30)
- bump Vault from 1.21 to 2.0 (#31)

## 0.1.3 (2026-04-03)

### Dependencies

- enable dependabot cooldown period (#17)
- bump actions/setup-go from 6.3.0 to 6.4.0 (#18)
- bump github.com/go-jose/go-jose/v4 from 4.1.3 to 4.1.4 (#19)
- bump github.com/hashicorp/go-secure-stdlib/plugincontainer from v0.4.2 to v0.5.0 (#20)

## 0.1.2 (2026-03-27)

### Features

- parse JSON:API error responses for cleaner error messages (#12)

### Improvements

- verify cache miss triggers refresh for new environments (#11)
- harden supply chain with vulnerability scanning, malware detection, and SBOMs (#13)

### Dependencies

- bump github.com/hashicorp/vault/api from 1.22.0 to 1.23.0 (#14)
- bump github.com/hashicorp/vault/sdk from 0.24.0 to 0.25.0 (#14)

## 0.1.1 (2026-03-21)

### Bug Fixes

- handle pagination in ListEnvironments (#4)
- add "rel:" prefix for release preparation PRs (#9)

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
