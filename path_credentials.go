package honeycombio

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/jharley/vault-plugin-secrets-honeycombio/internal/client"
)

const maxKeyNameLength = 100

type walEntry struct {
	RoleName string `json:"role_name"`
	KeyID    string `json:"key_id"`
}

func pathCredentials(b *honeycombBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role to generate credentials for",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
		},
		HelpSynopsis:    "Generate a Honeycomb API key",
		HelpDescription: "This path generates a dynamic Honeycomb API key based on the named role.",
	}
}

func (b *honeycombBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string) //nolint:forcetypeassert

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	keyName := generateKeyName(roleName)
	b.Logger().Debug("generating API key", "role", roleName, "key_name", keyName, "key_type", role.KeyType, "environment", role.Environment)

	envID, err := b.resolveEnvironmentID(ctx, req.Storage, role.Environment)
	if err != nil {
		return nil, fmt.Errorf("resolving environment: %w", err)
	}

	apiKey, err := c.CreateAPIKey(ctx, &client.CreateAPIKeyRequest{
		Name:          keyName,
		KeyType:       role.KeyType,
		EnvironmentID: envID,
		Permissions: client.APIKeyPermissions{
			CreateDatasets:     role.Permissions.CreateDatasets,
			SendEvents:         role.Permissions.SendEvents,
			ManageMarkers:      role.Permissions.ManageMarkers,
			ManageTriggers:     role.Permissions.ManageTriggers,
			ManageBoards:       role.Permissions.ManageBoards,
			RunQueries:         role.Permissions.RunQueries,
			ManageColumns:      role.Permissions.ManageColumns,
			ManageSLOs:         role.Permissions.ManageSLOs,
			ManageRecipients:   role.Permissions.ManageRecipients,
			ReadServiceMaps:    role.Permissions.ReadServiceMaps,
			VisibleTeamMembers: role.Permissions.VisibleTeamMembers,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating API key: %w", err)
	}
	b.Logger().Debug("API key created", "role", roleName, "key_id", apiKey.ID, "key_name", apiKey.Name)

	// Write WAL entry after creation for crash recovery.
	//
	// NOTE: The WAL is written after the key is created (not before) because
	// we need the key ID for cleanup. This leaves a small window where a crash
	// between key creation and WAL write could orphan a key in Honeycomb. This
	// is a deliberate trade-off — the Honeycomb API does not support listing
	// keys by name prefix, so a pre-creation WAL with no key ID cannot be used
	// to find and clean up the orphan. The window is very small (single storage
	// write) and orphaned keys can be identified by their "vault-" name prefix
	// in the Honeycomb UI.
	walID, err := framework.PutWAL(ctx, req.Storage, walRollbackKind, &walEntry{
		RoleName: roleName,
		KeyID:    apiKey.ID,
	})
	if err != nil {
		// WAL write failed; clean up the key we just created
		_ = c.DeleteAPIKey(ctx, apiKey.ID)
		return nil, fmt.Errorf("writing WAL entry: %w", err)
	}

	// Defer WAL deletion — lease management handles revocation from here
	defer func() {
		_ = framework.DeleteWAL(ctx, req.Storage, walID)
	}()

	data := map[string]any{
		"key_id":     apiKey.ID,
		"key_secret": apiKey.Secret,
		"key_type":   apiKey.KeyType,
		"key_name":   apiKey.Name,
	}

	internalData := map[string]any{
		"key_id":    apiKey.ID,
		"role_name": roleName,
	}

	resp := b.Secret(secretKeyType).Response(data, internalData)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func generateKeyName(roleName string) string {
	randBytes := make([]byte, 4) // 8 hex chars
	rand.Read(randBytes)
	suffix := hex.EncodeToString(randBytes)
	prefix := "vault-"
	maxRoleLen := maxKeyNameLength - len(prefix) - 1 - len(suffix)
	if len(roleName) > maxRoleLen {
		roleName = roleName[:maxRoleLen]
	}
	return fmt.Sprintf("%s%s-%s", prefix, roleName, suffix)
}
