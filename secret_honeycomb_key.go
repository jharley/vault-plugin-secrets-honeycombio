package honeycombio

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretKeyType = "honeycomb_key"

// revokeTimeout bounds a single revocation attempt. Vault's expiration manager
// runs revocations in a bounded worker pool and retries with its own backoff,
// so holding a worker for the client's entire retry schedule starves lease
// expiration across the whole instance during a Honeycomb outage — measured at
// 89s for one failing delete, and worse with an unlucky jitter draw. Failing
// sooner and letting Vault retry is strictly better than occupying the worker.
//
// A var so tests can shorten it; nothing outside tests reassigns it.
var revokeTimeout = 60 * time.Second

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

	ctx, cancel := context.WithTimeout(ctx, revokeTimeout)
	defer cancel()

	// Every failure below returns an error rather than a warning. Returning
	// success would drop the lease while the key is still live in Honeycomb,
	// leaving nothing to find it by. An error keeps the lease: Vault retries,
	// and on exhaustion records it as irrevocable, where it shows up in
	// sys/leases?type=irrevocable and the vault.expire.num_irrevocable_leases
	// gauge. That is the mechanism operators already have for credentials that
	// could not be cleaned up, and `vault lease revoke -force` clears one once
	// the key has been deleted by hand.
	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("cannot revoke API key: client unavailable", "key_id", keyID, "error", err)
		return nil, fmt.Errorf("building client to revoke Honeycomb API key %s: %w", keyID, err)
	}

	// A management key belongs to exactly one team, so a key issued under a
	// different team cannot be deleted with the credential configured now. The
	// request would fail, and a 404 is indistinguishable from the key already
	// being gone — so it would be reported as a successful revocation.
	//
	// The current team is resolved from /2/auth, so this compares the lease
	// against ground truth and fires only when the mount has genuinely been
	// reconfigured onto another team's management key. Leases issued before
	// the team was recorded carry no slug and skip the check.
	if issuedTeam, _ := req.Secret.InternalData["team_slug"].(string); issuedTeam != "" {
		currentTeam, err := c.TeamSlug(ctx)
		if err != nil {
			b.Logger().Error("cannot revoke API key: team unresolved", "key_id", keyID, "error", err)
			return nil, fmt.Errorf("resolving team to revoke Honeycomb API key %s: %w", keyID, err)
		}

		if issuedTeam != currentTeam {
			// This provably cannot succeed on a later attempt, and wrapping
			// logical.ErrUnrecoverable would have Vault mark the lease
			// irrevocable at once rather than backing off six times first.
			// No secrets engine appears to do that, so the retry schedule is
			// left to run: it costs a few minutes and reaches the same place.
			b.Logger().Error("cannot revoke API key: issued under a different team",
				"key_id", keyID, "issued_team", issuedTeam, "configured_team", currentTeam)
			return nil, fmt.Errorf(
				"cannot revoke Honeycomb API key %s: it was issued in team %q but this mount is now "+
					"configured for team %q, so the current management key cannot delete it and the "+
					"key must be removed by hand",
				keyID, issuedTeam, currentTeam)
		}
	}

	b.Logger().Info("revoking API key", "key_id", keyID)
	if err := c.DeleteAPIKey(ctx, keyID); err != nil {
		b.Logger().Error("failed to revoke API key", "key_id", keyID, "error", err)
		return nil, fmt.Errorf("deleting Honeycomb API key %s: %w", keyID, err)
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
