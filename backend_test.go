package honeycombio

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/jsonapi"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowPlaintextAPIURL permits the plaintext endpoints served by httptest.
// api_url requires HTTPS unless this escape hatch is set.
func allowPlaintextAPIURL(t *testing.T) {
	t.Helper()
	t.Setenv("HONEYCOMB_ALLOW_INSECURE_URL", "true")
}

func newTestBackend(t *testing.T, ctx context.Context) (*honeycombBackend, logical.Storage, *httptest.Server) {
	t.Helper()
	allowPlaintextAPIURL(t)

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
	allowPlaintextAPIURL(t)

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
	allowPlaintextAPIURL(t)

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

func TestValidateAPIURL(t *testing.T) {
	t.Setenv(allowInsecureURLEnv, "")

	valid := []string{
		"https://api.honeycomb.io",
		"https://api.eu1.honeycomb.io",
		"https://honeycomb.invalid:8443/prefix",
	}
	for _, u := range valid {
		t.Run("accepts "+u, func(t *testing.T) {
			assert.NoError(t, validateAPIURL(u))
		})
	}

	invalid := map[string]string{
		"plaintext":      "http://honeycomb.invalid",
		"no host":        "https://",
		"unknown scheme": "ftp://honeycomb.invalid",
		"missing scheme": "honeycomb.invalid",
		"not a url":      "://nonsense",
	}
	for name, u := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			assert.Error(t, validateAPIURL(u))
		})
	}
}

func TestValidateAPIURL_EscapeHatchAllowsPlaintext(t *testing.T) {
	t.Setenv(allowInsecureURLEnv, "")
	assert.Error(t, validateAPIURL("http://honeycomb.invalid"),
		"plaintext must be rejected without the escape hatch")

	allowPlaintextAPIURL(t)
	assert.NoError(t, validateAPIURL("http://honeycomb.invalid"),
		"escape hatch must permit plaintext")

	assert.Error(t, validateAPIURL("ftp://honeycomb.invalid"),
		"escape hatch must not permit non-HTTP schemes")
}

// TestConfigWrite_RejectsPlaintextURL verifies that api_url must use HTTPS.
// A plaintext endpoint sends the Honeycomb management key over the wire in
// cleartext on every request.
func TestConfigWrite_RejectsPlaintextURL(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)
	t.Setenv("HONEYCOMB_ALLOW_INSECURE_URL", "")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError(), "plaintext api_url should be rejected")
	assert.Contains(t, resp.Error().Error(), "https")
}

// TestConfigWrite_AllowsPlaintextURLWithEscapeHatch verifies the documented
// development escape hatch re-enables plaintext endpoints.
func TestConfigWrite_AllowsPlaintextURLWithEscapeHatch(t *testing.T) {
	ctx := context.Background()

	for _, value := range []string{"true", "1", "TRUE"} {
		t.Run(value, func(t *testing.T) {
			b, storage, srv := newTestBackend(t, ctx)
			t.Setenv("HONEYCOMB_ALLOW_INSECURE_URL", value)

			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Storage:   storage,
				Data: map[string]any{
					"api_key_id":     "hcxmk_testkey",
					"api_key_secret": "supersecret",
					"api_url":        srv.URL,
				},
			})
			require.NoError(t, err)
			assert.False(t, resp.IsError(), "escape hatch should permit plaintext api_url")
		})
	}
}

func TestConfigWrite_RejectsMalformedURL(t *testing.T) {
	ctx := context.Background()

	// Every case must be rejected before any network call is attempted;
	// hosts use the reserved .invalid TLD so a regression cannot reach out.
	for name, apiURL := range map[string]string{
		"not a url":          "://nonsense",
		"no host":            "https://",
		"unknown scheme":     "ftp://honeycomb.invalid",
		"missing scheme":     "honeycomb.invalid",
		"invalid characters": "https://honey comb.invalid",
	} {
		t.Run(name, func(t *testing.T) {
			b, storage, _ := newTestBackend(t, ctx)

			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Storage:   storage,
				Data: map[string]any{
					"api_key_id":     "hcxmk_testkey",
					"api_key_secret": "supersecret",
					"api_url":        apiURL,
				},
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.True(t, resp.IsError(), "malformed api_url %q should be rejected", apiURL)
			// Pin the rejection to api_url validation. Without this the test
			// is satisfied by an incidental connection error from client.New,
			// and passes even with the validation removed.
			assert.ErrorContains(t, resp.Error(), "api_url",
				"should be rejected by api_url validation, before any network call")
		})
	}
}

// TestStoredPlaintextURLRejectedOnUse verifies that an api_url stored before
// HTTPS was enforced does not keep shipping the management key in cleartext.
// Validation on write alone leaves existing configs unprotected.
func TestStoredPlaintextURLRejectedOnUse(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	// Store a plaintext URL the way an older version would have.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]any{
			"api_key_id":     "hcxmk_testkey",
			"api_key_secret": "supersecret",
			"api_url":        srv.URL,
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Drop the escape hatch and the cached client, as a restart would.
	t.Setenv(allowInsecureURLEnv, "")
	b.reset()

	_, err = b.getClient(ctx, storage)
	assert.ErrorContains(t, err, "https",
		"a stored plaintext api_url must be rejected on use, not silently honoured")
}

// TestConfigRead_WarnsOnPlaintextURL surfaces a stored plaintext endpoint to
// an operator reading the config.
func TestConfigRead_WarnsOnPlaintextURL(t *testing.T) {
	ctx := context.Background()
	b, storage, srv := newTestBackend(t, ctx)

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: storage,
		Data: map[string]any{
			"api_key_id": "hcxmk_testkey", "api_key_secret": "supersecret", "api_url": srv.URL,
		},
	})
	require.NoError(t, err)

	t.Setenv(allowInsecureURLEnv, "")
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: storage,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Warnings, "reading a plaintext config should warn the operator")
}

// TestCredentialsPath_RequestsHAForwarding verifies the creds path asks Vault
// to forward the request. It writes a WAL entry to storage, which is read-only
// on a performance standby or secondary.
func TestCredentialsPath_RequestsHAForwarding(t *testing.T) {
	props := pathCredentials(backend()).Operations[logical.ReadOperation].Properties()

	assert.True(t, props.ForwardPerformanceStandby,
		"creds path writes a WAL entry and must be forwarded from performance standbys")
	assert.True(t, props.ForwardPerformanceSecondary,
		"creds path writes a WAL entry and must be forwarded from performance secondaries")
}

func TestRoleWrite_RejectsTTLAboveMaxTTL(t *testing.T) {
	ctx := context.Background()
	b, storage, _ := newTestBackend(t, ctx)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-ttl",
		Storage:   storage,
		Data: map[string]any{
			"key_type":    "ingest",
			"environment": "production",
			"send_events": false,

			"create_datasets": true,
			"ttl":             "24h",
			"max_ttl":         "1h",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError(), "ttl greater than max_ttl should be rejected")
	assert.Contains(t, resp.Error().Error(), "max_ttl")
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

// newRevokeFailureBackend builds a backend whose DELETE requests always fail
// with the given status.
func newRevokeFailureBackend(t *testing.T, ctx context.Context, deleteStatus int) (*honeycombBackend, logical.Storage) {
	t.Helper()
	allowPlaintextAPIURL(t)

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
			w.WriteHeader(deleteStatus)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	require.NoError(t, b.Setup(ctx, config))

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

	return b, config.StorageView
}

// TestSecretRevoke_TransientFailureReturnsError verifies that a transient
// upstream failure surfaces as an error so Vault retries revocation. Reporting
// success would drop the lease while the key stays live in Honeycomb.
func TestSecretRevoke_TransientFailureReturnsError(t *testing.T) {
	ctx := context.Background()

	for name, status := range map[string]int{
		"server error":    http.StatusInternalServerError,
		"bad gateway":     http.StatusBadGateway,
		"rate limited":    http.StatusTooManyRequests,
		"gateway timeout": http.StatusGatewayTimeout,
		"unavailable":     http.StatusServiceUnavailable,
		"request timeout": http.StatusRequestTimeout,
	} {
		t.Run(name, func(t *testing.T) {
			b, storage := newRevokeFailureBackend(t, ctx, status)

			_, err := b.secretKeyRevoke(ctx, &logical.Request{
				Storage: storage,
				Secret: &logical.Secret{
					InternalData: map[string]any{
						"key_id":    "hcxik_faildelete",
						"role_name": "test-role",
					},
				},
			}, &framework.FieldData{})
			require.Error(t, err, "transient revocation failure must be retryable")
			assert.Contains(t, err.Error(), "hcxik_faildelete")
		})
	}
}

// TestSecretRevoke_TransientAuthFailureReturnsError verifies that a transient
// failure while building the client is retried too. Revocation reaches this
// path on any cold start (after a config write, plugin reload or Vault
// restart), where /2/auth is called before the delete.
func TestSecretRevoke_TransientAuthFailureReturnsError(t *testing.T) {
	ctx := context.Background()
	allowPlaintextAPIURL(t)

	var authStatus atomic.Int32
	authStatus.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status := authStatus.Load(); status != http.StatusOK {
			w.WriteHeader(int(status))
			return
		}
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
	}))
	t.Cleanup(srv.Close)

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := backend()
	require.NoError(t, b.Setup(ctx, config))

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: config.StorageView,
		Data: map[string]any{"api_key_id": "hcxmk_testkey", "api_key_secret": "s", "api_url": srv.URL},
	})
	require.NoError(t, err)

	// Simulate a cold start during a Honeycomb outage: the cached client is
	// gone and /2/auth is failing.
	b.reset()
	authStatus.Store(http.StatusServiceUnavailable)

	// Short deadline: the assertion is that a transient failure surfaces as
	// an error, not how long the retry schedule runs.
	revokeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	t.Cleanup(cancel)
	_, err = b.secretKeyRevoke(revokeCtx, &logical.Request{
		Storage: config.StorageView,
		Secret: &logical.Secret{
			InternalData: map[string]any{"key_id": "hcxik_live", "role_name": "test-role"},
		},
	}, &framework.FieldData{})
	assert.Error(t, err, "a transient auth failure must be retried, not reported as revoked")
}

// TestSecretRevoke_PermanentFailureWarns verifies that an unrecoverable
// failure warns and lets the lease expire, rather than making Vault retry a
// revocation that can never succeed.
func TestSecretRevoke_PermanentFailureWarns(t *testing.T) {
	ctx := context.Background()

	for name, status := range map[string]int{
		"unauthorized": http.StatusUnauthorized,
		"forbidden":    http.StatusForbidden,
		"bad request":  http.StatusBadRequest,
	} {
		t.Run(name, func(t *testing.T) {
			b, storage := newRevokeFailureBackend(t, ctx, status)

			resp, err := b.secretKeyRevoke(ctx, &logical.Request{
				Storage: storage,
				Secret: &logical.Secret{
					InternalData: map[string]any{
						"key_id":    "hcxik_faildelete",
						"role_name": "test-role",
					},
				},
			}, &framework.FieldData{})
			require.NoError(t, err, "permanent failure should not be retried forever")
			require.NotNil(t, resp)
			require.Len(t, resp.Warnings, 1)
			assert.Contains(t, resp.Warnings[0], "hcxik_faildelete")
		})
	}
}

func TestEnvCacheHit(t *testing.T) {
	ctx := context.Background()
	allowPlaintextAPIURL(t)

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
	allowPlaintextAPIURL(t)

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
	allowPlaintextAPIURL(t)

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
