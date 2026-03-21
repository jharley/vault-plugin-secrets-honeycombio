package honeycombio

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/jsonapi"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestBackend(t *testing.T, ctx context.Context) (*honeycombBackend, logical.Storage, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2/auth":
			w.Header().Set("Content-Type", jsonapi.MediaType)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":   "hcxmk_testkey",
					"type": "api-keys",
					"attributes": map[string]any{
						"name":     "test key",
						"key_type": "management",
						"disabled": false,
						"scopes":   []string{"api-keys:write"},
					},
					"relationships": map[string]any{
						"team": map[string]any{
							"data": map[string]any{
								"id":   "hcxtm_team1",
								"type": "teams",
							},
						},
					},
				},
				"included": []map[string]any{
					{
						"id":   "hcxtm_team1",
						"type": "teams",
						"attributes": map[string]any{
							"name": "Test Team",
							"slug": "test-team",
						},
					},
				},
			})
		case "/2/teams/test-team/environments":
			w.Header().Set("Content-Type", jsonapi.MediaType)
			json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{
						"id":   "hcxen_prod123",
						"type": "environments",
						"attributes": map[string]any{
							"name": "Production",
							"slug": "production",
						},
					},
				},
			})
		case "/2/teams/test-team/api-keys":
			if r.Method == http.MethodPost {
				w.Header().Set("Content-Type", jsonapi.MediaType)
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"id":   "hcxik_generated123",
						"type": "api-keys",
						"attributes": map[string]any{
							"name":     "vault-generated-key",
							"key_type": "ingest",
							"secret":   "generatedSecretValue",
							"disabled": false,
						},
					},
				})
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case "/2/teams/test-team/api-keys/hcxik_torevoke",
			"/2/teams/test-team/api-keys/hcxik_generated123":
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	err := b.Setup(ctx, config)
	require.NoError(t, err)

	return b, config.StorageView, srv
}

func TestConfigWriteRead(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write config
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read config
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "hcxmk_testkey", resp.Data["api_key_id"])
	assert.Equal(t, "<redacted>", resp.Data["api_key_secret"])
	assert.Equal(t, srv.URL, resp.Data["api_url"])
	assert.Equal(t, "test-team", resp.Data["team_slug"])
}

func TestConfigWrite_MissingFields(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]any{},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
}

func TestConfigWrite_BadCredentials(t *testing.T) {
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	require.NoError(t, b.Setup(ctx, config))

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   config.StorageView,
		Data: map[string]any{
			"api_key_id":     "hcxmk_badkey",
			"api_key_secret": "badsecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Data["error"], "failed to validate credentials")
}

func TestConfigWrite_MissingScopeRejected(t *testing.T) {
	ctx := context.Background()

	// Mock server returning a management key without api-keys:write scope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", jsonapi.MediaType)
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id": "hcxmk_readonly", "type": "api-keys",
				"attributes": map[string]any{
					"name": "read-only key", "key_type": "management",
					"disabled": false, "scopes": []string{"environments:read"},
				},
				"relationships": map[string]any{
					"team": map[string]any{"data": map[string]any{"id": "hcxtm_team1", "type": "teams"}},
				},
			},
			"included": []map[string]any{
				{"id": "hcxtm_team1", "type": "teams", "attributes": map[string]any{"name": "Test Team", "slug": "test-team"}},
			},
		})
	}))
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	require.NoError(t, b.Setup(ctx, config))

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   config.StorageView,
		Data: map[string]any{
			"api_key_id":     "hcxmk_readonly",
			"api_key_secret": "secret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Data["error"], "api-keys:write")
}

func TestRoleWriteRead(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	// Create a configuration role with multiple permissions
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "configuration",
			"environment":     "production",
			"create_datasets": true,
			"send_events":     true,
			"manage_markers":  true,
			"ttl":             "1h",
			"max_ttl":         "24h",
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read it back
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-role",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "configuration", resp.Data["key_type"])
	assert.Equal(t, "production", resp.Data["environment"])
	assert.Equal(t, true, resp.Data["create_datasets"])
	assert.Equal(t, true, resp.Data["send_events"])
	assert.Equal(t, true, resp.Data["manage_markers"])
	assert.Equal(t, false, resp.Data["manage_triggers"])
	assert.Equal(t, false, resp.Data["manage_boards"])
	assert.Equal(t, false, resp.Data["run_queries"])
	assert.Equal(t, false, resp.Data["manage_columns"])
	assert.Equal(t, false, resp.Data["manage_slos"])
	assert.Equal(t, false, resp.Data["manage_recipients"])
	assert.Equal(t, false, resp.Data["read_service_maps"])
	assert.Equal(t, false, resp.Data["visible_team_members"])
}

func TestRolePartialUpdate(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	// Create a role
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/partial-test",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "configuration",
			"environment":     "production",
			"create_datasets": true,
			"send_events":     true,
			"ttl":             "1h",
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Partial update — only change TTL, leave everything else intact
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/partial-test",
		Storage:   storage,
		Data: map[string]any{
			"ttl": "2h",
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read back — permissions and environment should be preserved
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/partial-test",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "configuration", resp.Data["key_type"])
	assert.Equal(t, "production", resp.Data["environment"])
	assert.Equal(t, true, resp.Data["create_datasets"])
	assert.Equal(t, true, resp.Data["send_events"])
	assert.Equal(t, int64(7200), resp.Data["ttl"])
	assert.Equal(t, int64(0), resp.Data["max_ttl"])
}

func TestRoleWrite_IngestRejectsConfigPermissions(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/ingest-role",
		Storage:   storage,
		Data: map[string]any{
			"key_type":    "ingest",
			"environment": "production",
			"send_events": true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
}

func TestRoleWrite_InvalidKeyType(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "management",
			"environment":     "production",
			"create_datasets": true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
}

func TestRoleWrite_NoPermissions(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/no-perms",
		Storage:   storage,
		Data: map[string]any{
			"key_type":    "configuration",
			"environment": "production",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
}

func TestRoleList(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	// Create two roles
	for _, name := range []string{"role-a", "role-b"} {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/" + name,
			Storage:   storage,
			Data: map[string]any{
				"key_type":        "configuration",
				"environment":     "production",
				"create_datasets": true,
			},
		})
		require.NoError(t, err)
		require.Nil(t, resp)
	}

	// List roles
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok, "expected keys to be []string")
	assert.Len(t, keys, 2)
}

func TestRoleDelete(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	// Create a role
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/doomed",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "configuration",
			"environment":     "production",
			"create_datasets": true,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Delete it
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/doomed",
		Storage:   storage,
	})
	require.NoError(t, err)
	assert.Nil(t, resp)

	// Read should return nil
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/doomed",
		Storage:   storage,
	})
	require.NoError(t, err)
	assert.Nil(t, resp)
}

func TestSecretRevoke(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write config
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Simulate a revoke
	resp, err = b.secretKeyRevoke(ctx, &logical.Request{
		Storage: storage,
		Secret: &logical.Secret{
			InternalData: map[string]any{
				"key_id": "hcxik_torevoke",
			},
		},
	}, &framework.FieldData{})
	require.NoError(t, err)
	assert.Nil(t, resp)
}

func TestRenewAfterRoleDeletion(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write config
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Create role "ephemeral"
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/ephemeral",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "ingest",
			"environment":     "production",
			"create_datasets": true,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Construct a secret with InternalData referencing the role
	secret := &logical.Secret{
		InternalData: map[string]any{
			"role_name": "ephemeral",
		},
	}

	// Renew should succeed while role exists
	resp, err = b.secretKeyRenew(ctx, &logical.Request{
		Storage: storage,
		Secret:  secret,
	}, &framework.FieldData{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Delete the role
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/ephemeral",
		Storage:   storage,
	})
	require.NoError(t, err)
	assert.Nil(t, resp)

	// Renew should fail because role no longer exists
	_, err = b.secretKeyRenew(ctx, &logical.Request{
		Storage: storage,
		Secret:  secret,
	}, &framework.FieldData{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer exists")
}

func TestConfigDelete(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write then delete
	b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "secret",
			"api_url":        srv.URL,
		},
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	})
	require.NoError(t, err)
	assert.Nil(t, resp)

	// Read should return nil
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	require.NoError(t, err)
	assert.Nil(t, resp)
}

func TestCredentialGeneration(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write config
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Create ingest role
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "ingest",
			"environment":     "production",
			"create_datasets": true,
			"ttl":             "1h",
			"max_ttl":         "24h",
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read credentials
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.IsError(), "unexpected error: %v", resp.Error())

	// Assert key data
	assert.Equal(t, "hcxik_generated123", resp.Data["key_id"])
	assert.Equal(t, "generatedSecretValue", resp.Data["key_secret"])

	// Assert secret metadata
	require.NotNil(t, resp.Secret)
	assert.Equal(t, "hcxik_generated123", resp.Secret.InternalData["key_id"])
	assert.Equal(t, "test-role", resp.Secret.InternalData["role_name"])
}

func TestCredentialGeneration_NoConfig(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	// Create role without config
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "ingest",
			"environment":     "production",
			"create_datasets": true,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read credentials should fail
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   storage,
	})
	require.Error(t, err)
}

func TestCredentialGeneration_NoRole(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write config
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read credentials for nonexistent role
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nonexistent",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
}

func TestGenerateKeyName(t *testing.T) {
	// Normal name
	name := generateKeyName("my-role")
	assert.True(t, strings.HasPrefix(name, "vault-my-role-"))
	assert.Len(t, name, len("vault-my-role-")+8) // 8 hex chars

	// Very long role name should be truncated to fit 100 char limit
	longRole := strings.Repeat("a", 200)
	longName := generateKeyName(longRole)
	assert.LessOrEqual(t, len(longName), maxKeyNameLength)
	assert.True(t, strings.HasPrefix(longName, "vault-"))

	// Empty role name
	emptyName := generateKeyName("")
	assert.True(t, strings.HasPrefix(emptyName, "vault--"))
}

func TestWALRollback(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write config
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Call walRollback directly with a WAL entry
	entry := &walEntry{
		RoleName: "test-role",
		KeyID:    "hcxik_torevoke",
	}

	err = b.walRollback(ctx, &logical.Request{
		Storage: storage,
	}, walRollbackKind, entry)
	require.NoError(t, err)
}

func TestWALRollback_EmptyKeyID(t *testing.T) {
	ctx := context.Background()
	b, _, _ := newTestBackend(t, ctx)

	entry := &walEntry{
		RoleName: "test-role",
		KeyID:    "",
	}

	err := b.walRollback(ctx, &logical.Request{}, walRollbackKind, entry)
	require.NoError(t, err)
}

func TestWALRollback_NoConfig(t *testing.T) {
	ctx := context.Background()
	b, _, _ := newTestBackend(t, ctx)

	// No config written — getClient will fail
	entry := &walEntry{
		RoleName: "test-role",
		KeyID:    "hcxik_orphaned",
	}

	err := b.walRollback(ctx, &logical.Request{
		Storage: &logical.InmemStorage{},
	}, walRollbackKind, entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting client for WAL rollback")
}

func TestSecretRevoke_ClientUnavailable(t *testing.T) {
	ctx := context.Background()
	b, _, _ := newTestBackend(t, ctx)

	// No config — client cannot be created
	resp, err := b.secretKeyRevoke(ctx, &logical.Request{
		Storage: &logical.InmemStorage{},
		Secret: &logical.Secret{
			InternalData: map[string]any{
				"key_id":    "hcxik_orphaned",
				"role_name": "test-role",
			},
		},
	}, &framework.FieldData{})
	require.NoError(t, err, "should not return error — returns warning instead")
	require.NotNil(t, resp)
	require.Len(t, resp.Warnings, 1)
	assert.Contains(t, resp.Warnings[0], "hcxik_orphaned")
}

func TestSecretRevoke_DeleteFails(t *testing.T) {
	ctx := context.Background()

	// Mock server that accepts auth but returns 500 on delete
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/2/auth":
			w.Header().Set("Content-Type", jsonapi.MediaType)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id": "hcxmk_testkey", "type": "api-keys",
					"attributes": map[string]any{
						"name": "test key", "key_type": "management",
						"disabled": false, "scopes": []string{"api-keys:write"},
					},
					"relationships": map[string]any{
						"team": map[string]any{"data": map[string]any{"id": "hcxtm_team1", "type": "teams"}},
					},
				},
				"included": []map[string]any{
					{"id": "hcxtm_team1", "type": "teams", "attributes": map[string]any{"name": "Test Team", "slug": "test-team"}},
				},
			})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	require.NoError(t, b.Setup(ctx, config))

	// Write config
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   config.StorageView,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)

	// Speed up retries for test — getClient caches the client after config write
	cachedClient, _ := b.getClient(ctx, config.StorageView)
	cachedClient.SetRetryWait(0, 0)

	// Revoke should return warning, not error
	resp, err := b.secretKeyRevoke(ctx, &logical.Request{
		Storage: config.StorageView,
		Secret: &logical.Secret{
			InternalData: map[string]any{
				"key_id":    "hcxik_faildelete",
				"role_name": "test-role",
			},
		},
	}, &framework.FieldData{})
	require.NoError(t, err, "should not return error — returns warning instead")
	require.NotNil(t, resp)
	require.Len(t, resp.Warnings, 1)
	assert.Contains(t, resp.Warnings[0], "hcxik_faildelete")
}

func TestEnvCacheHit(t *testing.T) {
	ctx := context.Background()

	envListCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2/auth":
			w.Header().Set("Content-Type", jsonapi.MediaType)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id": "hcxmk_testkey", "type": "api-keys",
					"attributes": map[string]any{
						"name": "test key", "key_type": "management",
						"disabled": false, "scopes": []string{"api-keys:read", "api-keys:write"},
					},
					"relationships": map[string]any{
						"team": map[string]any{"data": map[string]any{"id": "hcxtm_team1", "type": "teams"}},
					},
				},
				"included": []map[string]any{
					{"id": "hcxtm_team1", "type": "teams", "attributes": map[string]any{"name": "Test Team", "slug": "test-team"}},
				},
			})
		case "/2/teams/test-team/environments":
			envListCalls++
			w.Header().Set("Content-Type", jsonapi.MediaType)
			json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": "hcxen_prod123", "type": "environments", "attributes": map[string]any{"name": "Production", "slug": "production"}},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	require.NoError(t, b.Setup(ctx, config))

	storage := config.StorageView

	// Write config so getClient works
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)

	// First resolve — should call the API
	id, err := b.resolveEnvironmentID(ctx, storage, "production")
	require.NoError(t, err)
	assert.Equal(t, "hcxen_prod123", id)
	assert.Equal(t, 1, envListCalls, "should have called ListEnvironments once")

	// Second resolve — should use cache
	id, err = b.resolveEnvironmentID(ctx, storage, "production")
	require.NoError(t, err)
	assert.Equal(t, "hcxen_prod123", id)
	assert.Equal(t, 1, envListCalls, "should still be 1 (cache hit)")
}

func TestEnvCacheExpiry(t *testing.T) {
	ctx := context.Background()

	envListCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2/auth":
			w.Header().Set("Content-Type", jsonapi.MediaType)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id": "hcxmk_testkey", "type": "api-keys",
					"attributes": map[string]any{
						"name": "test key", "key_type": "management",
						"disabled": false, "scopes": []string{"api-keys:read", "api-keys:write"},
					},
					"relationships": map[string]any{
						"team": map[string]any{"data": map[string]any{"id": "hcxtm_team1", "type": "teams"}},
					},
				},
				"included": []map[string]any{
					{"id": "hcxtm_team1", "type": "teams", "attributes": map[string]any{"name": "Test Team", "slug": "test-team"}},
				},
			})
		case "/2/teams/test-team/environments":
			envListCalls++
			w.Header().Set("Content-Type", jsonapi.MediaType)
			json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": "hcxen_prod123", "type": "environments", "attributes": map[string]any{"name": "Production", "slug": "production"}},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	require.NoError(t, b.Setup(ctx, config))

	storage := config.StorageView

	// Write config so getClient works
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)

	// Populate cache
	id, err := b.resolveEnvironmentID(ctx, storage, "production")
	require.NoError(t, err)
	assert.Equal(t, "hcxen_prod123", id)
	assert.Equal(t, 1, envListCalls)

	// Expire the cache by backdating the expiry
	b.lock.Lock()
	b.envCacheExpiry = time.Now().Add(-1 * time.Second)
	b.lock.Unlock()

	// Next resolve should re-fetch
	id, err = b.resolveEnvironmentID(ctx, storage, "production")
	require.NoError(t, err)
	assert.Equal(t, "hcxen_prod123", id)
	assert.Equal(t, 2, envListCalls, "should have re-fetched after expiry")
}

func TestEnvCacheMiss(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write config so client can be created
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)

	// Resolve a slug that doesn't exist
	_, err = b.resolveEnvironmentID(ctx, storage, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Contains(t, err.Error(), "not found")
}

func TestEnvCacheMissRefreshesOnNewEnvironment(t *testing.T) {
	ctx := context.Background()

	envListCalls := 0
	hasNewEnv := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2/auth":
			w.Header().Set("Content-Type", jsonapi.MediaType)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id": "hcxmk_testkey", "type": "api-keys",
					"attributes": map[string]any{
						"name": "test key", "key_type": "management",
						"disabled": false, "scopes": []string{"api-keys:write"},
					},
					"relationships": map[string]any{
						"team": map[string]any{"data": map[string]any{"id": "hcxtm_team1", "type": "teams"}},
					},
				},
				"included": []map[string]any{
					{"id": "hcxtm_team1", "type": "teams", "attributes": map[string]any{"name": "Test Team", "slug": "test-team"}},
				},
			})
		case "/2/teams/test-team/environments":
			envListCalls++
			w.Header().Set("Content-Type", jsonapi.MediaType)
			envs := []map[string]any{
				{"id": "hcxen_prod123", "type": "environments", "attributes": map[string]any{"name": "Production", "slug": "production"}},
			}
			if hasNewEnv {
				envs = append(envs, map[string]any{
					"id": "hcxen_staging456", "type": "environments", "attributes": map[string]any{"name": "Staging", "slug": "staging"},
				})
			}
			json.NewEncoder(w).Encode(map[string]any{"data": envs})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	require.NoError(t, b.Setup(ctx, config))

	storage := config.StorageView

	// Write config
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)

	// Populate cache with production only
	id, err := b.resolveEnvironmentID(ctx, storage, "production")
	require.NoError(t, err)
	assert.Equal(t, "hcxen_prod123", id)
	assert.Equal(t, 1, envListCalls)

	// Cache is valid, but staging doesn't exist yet — should refresh
	_, err = b.resolveEnvironmentID(ctx, storage, "staging")
	require.Error(t, err, "staging not in API yet")
	assert.Equal(t, 2, envListCalls, "should have re-fetched on miss despite valid cache")

	// Now add staging to the API
	hasNewEnv = true

	// Cache was just refreshed (without staging), so it's valid.
	// A miss should still trigger another refresh.
	id, err = b.resolveEnvironmentID(ctx, storage, "staging")
	require.NoError(t, err)
	assert.Equal(t, "hcxen_staging456", id)
	assert.Equal(t, 3, envListCalls, "should have re-fetched again for new environment")

	// Now a hit for production should NOT re-fetch
	id, err = b.resolveEnvironmentID(ctx, storage, "production")
	require.NoError(t, err)
	assert.Equal(t, "hcxen_prod123", id)
	assert.Equal(t, 3, envListCalls, "should use cache for known environment")
}

func TestEnvCacheResetOnConfigChange(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Write config
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)

	// Populate cache
	id, err := b.resolveEnvironmentID(ctx, storage, "production")
	require.NoError(t, err)
	assert.Equal(t, "hcxen_prod123", id)

	// Verify cache is populated
	b.lock.RLock()
	assert.NotNil(t, b.envCache)
	b.lock.RUnlock()

	// Rewrite config — should clear cache
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)

	// Cache should be nil after config change
	b.lock.RLock()
	assert.Nil(t, b.envCache)
	b.lock.RUnlock()
}

func TestFullLifecycle(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Step 1: Configure
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Step 2: Create role
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/lifecycle-role",
		Storage:   storage,
		Data: map[string]any{
			"key_type":        "ingest",
			"environment":     "production",
			"create_datasets": true,
			"ttl":             "1h",
			"max_ttl":         "24h",
		},
	})
	require.NoError(t, err)
	require.Nil(t, resp)

	// Step 3: Generate credentials
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/lifecycle-role",
		Storage:   storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.IsError(), "unexpected error: %v", resp.Error())
	require.NotNil(t, resp.Secret)

	// Step 4: Renew
	renewResp, err := b.secretKeyRenew(ctx, &logical.Request{
		Storage: storage,
		Secret:  resp.Secret,
	}, &framework.FieldData{})
	require.NoError(t, err)
	require.NotNil(t, renewResp)
	assert.Equal(t, 1*time.Hour, renewResp.Secret.TTL)

	// Step 5: Revoke
	revokeResp, err := b.secretKeyRevoke(ctx, &logical.Request{
		Storage: storage,
		Secret:  resp.Secret,
	}, &framework.FieldData{})
	require.NoError(t, err)
	assert.Nil(t, revokeResp)
}
