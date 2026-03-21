package honeycombio

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretKeyType = "honeycomb_key"

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

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		// If we can't create a client (e.g., config deleted), we can't revoke
		// the key via the API. Warn and let the lease expire rather than
		// retrying indefinitely.
		b.Logger().Error("cannot revoke API key: client unavailable", "key_id", keyID, "error", err)
		return &logical.Response{
			Warnings: []string{fmt.Sprintf("failed to revoke Honeycomb API key %s: %s", keyID, err)},
		}, nil
	}

	b.Logger().Info("revoking API key", "key_id", keyID)
	if err := c.DeleteAPIKey(ctx, keyID); err != nil {
		// Log the error but allow the lease to expire. Returning an error
		// here would cause Vault to retry indefinitely, which is unhelpful
		// if the management key has been rotated or revoked (401/403).
		b.Logger().Error("failed to revoke API key", "key_id", keyID, "error", err)
		return &logical.Response{
			Warnings: []string{fmt.Sprintf("failed to delete Honeycomb API key %s: %s", keyID, err)},
		}, nil
	}

	return nil, nil
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
