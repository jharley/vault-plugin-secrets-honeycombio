# Honeycomb API Client

A minimal Go client for the [Honeycomb v2 Management API](https://docs.honeycomb.io/api/), purpose-built for the Vault secrets engine plugin.

This client covers only the endpoints needed by the plugin:

- `GET /2/auth` — validate management key and resolve team slug
- `GET /2/teams/{slug}/environments` — list environments
- `POST /2/teams/{slug}/api-keys` — create API keys
- `DELETE /2/teams/{slug}/api-keys/{id}` — delete API keys

The implementation is informed by the [Honeycomb OpenAPI specification](https://api.honeycomb.io/api.yaml) and uses [hashicorp/jsonapi](https://github.com/hashicorp/jsonapi) for JSON:API serialization. HTTP retries and rate-limit handling are provided by [hashicorp/go-retryablehttp](https://github.com/hashicorp/go-retryablehttp).

This package is internal to the plugin and not intended for external use.
