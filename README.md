# Vault Plugin: Honeycomb.io Secrets Engine

A [HashiCorp Vault](https://www.vaultproject.io) secrets engine plugin that dynamically generates [Honeycomb.io](https://www.honeycomb.io) API keys (Configuration Keys and Ingest Keys).

Keys are created on demand with configurable permissions and automatically revoked when the Vault lease expires, ensuring short-lived credentials with no manual cleanup.

## Getting Started

### Build

```sh
$ make build
```

The compiled plugin binary will be at `bin/vault-plugin-secrets-honeycombio`.

### Register and Enable

Configure Vault's `plugin_directory` in your server config, then:

```sh
$ vault plugin register \
    -sha256=$(shasum -a 256 bin/vault-plugin-secrets-honeycombio | cut -d' ' -f1) \
    secret vault-plugin-secrets-honeycombio

$ vault secrets enable -path=honeycomb vault-plugin-secrets-honeycombio
```

## Usage

### Configure the Backend

Provide a [Honeycomb Management Key](https://docs.honeycomb.io/configure/teams/manage-api-keys/) with `api-keys:write` scope:

```sh
$ vault write honeycomb/config \
    api_key_id="hcxmk_01abc..." \
    api_key_secret="..."
```

The plugin validates the keypair against the Honeycomb API and extracts the team slug automatically.

| Parameter        | Required | Description                                              |
|------------------|----------|----------------------------------------------------------|
| `api_key_id`     | yes      | Management API Key ID                                    |
| `api_key_secret` | yes      | Management API Key Secret                                |
| `api_url`        | no       | API base URL (default: `https://api.honeycomb.io`)       |

Set `api_url` to `https://api.eu1.honeycomb.io` for EU region environments.

### Create a Role

Roles define the key type, target environment, and permissions:

```sh
$ vault write honeycomb/roles/production-ingest \
    key_type=ingest \
    environment=production \
    create_datasets=true \
    ttl=1h \
    max_ttl=24h
```

```sh
$ vault write honeycomb/roles/dev-full-access \
    key_type=configuration \
    environment=development \
    create_datasets=true \
    send_events=true \
    run_queries=true \
    manage_columns=true \
    manage_boards=true \
    ttl=4h \
    max_ttl=72h
```

| Parameter            | Required | Description                                         |
|----------------------|----------|-----------------------------------------------------|
| `key_type`           | yes      | `configuration` or `ingest`                         |
| `environment`        | yes      | Honeycomb environment slug                          |
| `create_datasets`    | no       | Permission to create datasets                       |
| `send_events`        | no       | Permission to send events (configuration only)      |
| `manage_markers`     | no       | Permission to manage markers (configuration only)   |
| `manage_triggers`    | no       | Permission to manage triggers (configuration only)  |
| `manage_boards`      | no       | Permission to manage boards (configuration only)    |
| `run_queries`        | no       | Permission to run queries (configuration only)      |
| `manage_columns`     | no       | Permission to manage columns (configuration only)   |
| `manage_slos`        | no       | Permission to manage SLOs (configuration only)      |
| `manage_recipients`  | no       | Permission to manage recipients (configuration only)|
| `read_service_maps`  | no       | Permission to read service maps (configuration only)|
| `visible_team_members`| no     | Permission to view team members (configuration only)|
| `ttl`                | no       | Default lease TTL                                   |
| `max_ttl`            | no       | Maximum lease TTL                                   |

Ingest keys only support the `create_datasets` permission. At least one permission must be enabled.

### Generate Credentials

```sh
$ vault read honeycomb/creds/production-ingest
Key                Value
---                -----
lease_id           honeycomb/creds/production-ingest/abcd1234...
lease_duration     1h
lease_renewable    true
key_id             hcaik_01abc...
key_name           vault-production-ingest-f3a8b2c1
key_secret         ...
key_type           ingest
```

The `key_secret` is only available at creation time. Vault manages the lease — when it expires or is revoked, the key is deleted from Honeycomb.

### Renew and Revoke

```sh
$ vault lease renew honeycomb/creds/production-ingest/abcd1234...
$ vault lease revoke honeycomb/creds/production-ingest/abcd1234...
```

## Developing

**Requirements:** Go 1.26.1 (see `.go-version`)

```sh
$ make build    # compile the plugin binary
$ make test     # run unit and integration tests
$ make lint     # run golangci-lint
$ make testacc  # run acceptance tests against live Honeycomb API
```

### Acceptance Tests

Acceptance tests create and delete real API keys in Honeycomb. They require the following environment variables:

| Variable                | Description                        |
|-------------------------|------------------------------------|
| `VAULT_ACC`             | Set to `1` to enable               |
| `HONEYCOMB_KEY_ID`      | Management API Key ID              |
| `HONEYCOMB_KEY_SECRET`  | Management API Key Secret          |
| `HONEYCOMB_ENVIRONMENT` | Environment slug to test against   |
| `HONEYCOMB_API_URL`     | Optional, defaults to `https://api.honeycomb.io` |

Copy `.envrc.example` to `.envrc`, fill in values, and run `direnv allow` for local development.

### Docker Compose Validation

A Docker Compose environment runs both Vault and OpenBao with the plugin built, registered, and configured automatically:

```sh
$ make validate    # build and start both servers
$ make validate-down  # stop and clean up
```

Vault is available at `http://localhost:8200` and OpenBao at `http://localhost:8210` (root token: `root`).

```sh
# Vault
$ docker compose exec vault vault read honeycomb/creds/ingest-test

# OpenBao
$ docker compose exec openbao bao read honeycomb/creds/ingest-test
```

The containers read `HONEYCOMB_KEY_ID`, `HONEYCOMB_KEY_SECRET`, and `HONEYCOMB_ENVIRONMENT` from the host environment (loaded via `.envrc`). If credentials are not set, the plugin is enabled but not configured.

## Compatibility

This plugin uses the [HashiCorp Vault SDK](https://github.com/hashicorp/vault/tree/main/sdk) and is compatible with both [HashiCorp Vault](https://www.vaultproject.io) and [OpenBao](https://openbao.org).
