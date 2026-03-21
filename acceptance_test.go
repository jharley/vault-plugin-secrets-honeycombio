package honeycombio

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// accTestBackend creates a configured backend for acceptance tests.
// Skips the test if required env vars are not set.
func accTestBackend(t *testing.T) (*honeycombBackend, logical.Storage, string) {
	t.Helper()

	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("set VAULT_ACC=1 to run acceptance tests")
	}

	keyID := os.Getenv("HONEYCOMB_KEY_ID")
	keySecret := os.Getenv("HONEYCOMB_KEY_SECRET")
	if keyID == "" || keySecret == "" {
		t.Skip("set HONEYCOMB_KEY_ID and HONEYCOMB_KEY_SECRET to run acceptance tests")
	}

	apiURL := os.Getenv("HONEYCOMB_API_URL")
	if apiURL == "" {
		apiURL = "https://api.honeycomb.io"
	}

	envSlug := os.Getenv("HONEYCOMB_ENVIRONMENT")
	if envSlug == "" {
		t.Skip("set HONEYCOMB_ENVIRONMENT to an environment slug")
	}

	ctx := context.Background()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	err := b.Setup(ctx, config)
	require.NoError(t, err)

	// Configure
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   config.StorageView,
		Data: map[string]any{
			"api_key_id":     keyID,
			"api_key_secret": keySecret,
			"api_url":        apiURL,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp, "config write should return nil on success")

	return b, config.StorageView, envSlug
}

func TestAcceptance_IngestKey(t *testing.T) {
	ctx := context.Background()
	b, storage, envSlug := accTestBackend(t)

	// Create ingest role
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/acc-test-ingest",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "ingest",
			"environment":     envSlug,
			"create_datasets": true,
			"ttl":             "5m",
			"max_ttl":         "10m",
		},
	})
	require.NoError(t, err)
	assert.Nil(t, resp)

	// Generate credentials
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/acc-test-ingest",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "creds should not error: %v", resp)

	t.Logf("Generated ingest key: id=%s name=%s", resp.Data["key_id"], resp.Data["key_name"])

	require.NotNil(t, resp.Secret)
	assert.NotEmpty(t, resp.Data["key_id"])
	assert.NotEmpty(t, resp.Data["key_secret"])
	assert.Equal(t, "ingest", resp.Data["key_type"])

	// Revoke
	revokeResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   storage,
		Secret:    resp.Secret,
	})
	require.NoError(t, err)
	assert.True(t, revokeResp == nil || !revokeResp.IsError(), "revoke should succeed")

	t.Log("Ingest key revoked successfully")
}

func TestAcceptance_ConfigurationKey(t *testing.T) {
	ctx := context.Background()
	b, storage, envSlug := accTestBackend(t)

	// Create configuration role with multiple permissions
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/acc-test-config",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "configuration",
			"environment":     envSlug,
			"create_datasets": true,
			"send_events":     true,
			"run_queries":     true,
			"manage_columns":  true,
			"ttl":             "5m",
			"max_ttl":         "10m",
		},
	})
	require.NoError(t, err)
	assert.Nil(t, resp)

	// Generate credentials
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/acc-test-config",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "creds should not error: %v", resp)

	t.Logf("Generated configuration key: id=%s name=%s", resp.Data["key_id"], resp.Data["key_name"])

	require.NotNil(t, resp.Secret)
	assert.NotEmpty(t, resp.Data["key_id"])
	assert.NotEmpty(t, resp.Data["key_secret"])
	assert.Equal(t, "configuration", resp.Data["key_type"])

	// Revoke
	revokeResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   storage,
		Secret:    resp.Secret,
	})
	require.NoError(t, err)
	assert.True(t, revokeResp == nil || !revokeResp.IsError(), "revoke should succeed")

	t.Log("Configuration key revoked successfully")
}
