# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (March 21, 2026)

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
