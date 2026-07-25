package honeycombio

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/jharley/vault-plugin-secrets-honeycombio/internal/client"
)

const (
	secretKeyType = "honeycomb_key"

	// revokeClientTimeout bounds the client setup performed during revocation.
	revokeClientTimeout = 10 * time.Second
)

func secretHoneycombKey(b *honeycombBackend) *framework.Secret {
	return &framework.Secret{
		Type: secretKeyType,
		Fields: map[string]*framework.FieldSchema{
			"key_id": {
				Type:        framework.TypeString,
				Description: "Honeycomb API Key ID",
			},
			"key_secret": {
				Type:        framework.TypeString,
				Description: "Honeycomb API Key Secret",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: "Type of API key",
			},
			"key_name": {
				Type:        framework.TypeString,
				Description: "Name of the API key",
			},
		},
		Revoke: b.secretKeyRevoke,
		Renew:  b.secretKeyRenew,
	}
}

func (b *honeycombBackend) secretKeyRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keyID, ok := req.Secret.InternalData["key_id"].(string)
	if !ok || keyID == "" {
		return nil, fmt.Errorf("key_id not found in secret internal data")
	}

	// Building the client calls /2/auth, which retries on failure. Bound it so
	// a Honeycomb outage cannot occupy an expiration worker for the whole
	// retry schedule; Vault retries the revocation itself, with better
	// backoff than blocking here would give.
	clientCtx, cancel := context.WithTimeout(ctx, revokeClientTimeout)
	defer cancel()

	c, err := b.getClient(clientCtx, req.Storage)
	if err != nil {
		// A Honeycomb outage fails here on any cold path (after a config
		// write, plugin reload or restart). That is transient and must be
		// retried, or the lease is dropped while the key is still live.
		if isRetryableRevokeError(err) {
			b.Logger().Error("cannot revoke API key: client unavailable, will retry", "key_id", keyID, "error", err)
			return nil, fmt.Errorf("building client to revoke Honeycomb API key %s: %w", keyID, err)
		}

		// The configuration is gone or unusable. No amount of retrying will
		// fix that, so warn and let the lease expire.
		b.Logger().Error("cannot revoke API key: client unavailable, giving up", "key_id", keyID, "error", err)
		return &logical.Response{
			Warnings: []string{fmt.Sprintf("failed to revoke Honeycomb API key %s: %s", keyID, err)},
		}, nil
	}

	b.Logger().Info("revoking API key", "key_id", keyID)
	if err := c.DeleteAPIKey(ctx, keyID); err != nil {
		// A transient failure must surface as an error so Vault retries the
		// revocation. Reporting success would drop the lease while the key
		// stays valid in Honeycomb, leaving a live credential with nothing
		// tracking it.
		if isRetryableRevokeError(err) {
			b.Logger().Error("failed to revoke API key, will retry", "key_id", keyID, "error", err)
			return nil, fmt.Errorf("deleting Honeycomb API key %s: %w", keyID, err)
		}

		// A permanent failure cannot be fixed by retrying — the management
		// key has been rotated or lost its permissions. Warn and let the
		// lease expire rather than retrying until Vault gives up.
		b.Logger().Error("failed to revoke API key, giving up", "key_id", keyID, "error", err)
		return &logical.Response{
			Warnings: []string{fmt.Sprintf("failed to delete Honeycomb API key %s: %s", keyID, err)},
		}, nil
	}

	return nil, nil
}

// isRetryableRevokeError reports whether a revocation failure is worth
// retrying. Anything caused by the backend's own configuration is permanent;
// transport-level failures carry no status code and are treated as transient.
func isRetryableRevokeError(err error) bool {
	if errors.Is(err, errNotConfigured) {
		return false
	}
	var invalidCfg *invalidConfigError
	if errors.As(err, &invalidCfg) {
		return false
	}
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Retryable()
	}
	return true
}

func (b *honeycombBackend) secretKeyRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleName, ok := req.Secret.InternalData["role_name"].(string)
	if !ok || roleName == "" {
		return nil, fmt.Errorf("role_name not found in secret internal data")
	}

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		b.Logger().Warn("role no longer exists during renew", "role", roleName)
		return nil, fmt.Errorf("role %q no longer exists", roleName)
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}
