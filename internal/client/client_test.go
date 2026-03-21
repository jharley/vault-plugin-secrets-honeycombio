package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/jsonapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authResponse is the standard /2/auth JSON:API response used by test helpers.
const authResponse = `{
	"data": {
		"id": "key123",
		"type": "api-keys",
		"attributes": {
			"name": "test-key",
			"key_type": "management",
			"disabled": false,
			"scopes": ["api-keys:write"]
		},
		"relationships": {
			"team": {
				"data": {"id": "team456", "type": "teams"}
			}
		}
	},
	"included": [
		{
			"id": "team456",
			"type": "teams",
			"attributes": {
				"name": "My Team",
				"slug": "my-team"
			}
		}
	]
}`

// writeAuthResponse writes the standard auth response to w.
func writeAuthResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", jsonapi.MediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(authResponse))
}

// newTestServer creates a mock server that handles /2/auth and delegates
// other paths to the provided handler.
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2/auth" {
			writeAuthResponse(w)
			return
		}
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestClient creates a Client pointing at a test server that handles /2/auth
// plus any additional routes via the handler. Sets retry waits to near-zero
// for fast tests.
func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	ctx := context.Background()
	srv := newTestServer(t, handler)
	c, err := New(ctx, &Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)
	// Speed up retries for tests
	c.http.RetryWaitMin = 0
	c.http.RetryWaitMax = 0
	return c, srv
}

func TestNewClient(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, nil)

	c, err := New(ctx, &Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "my-team", c.TeamSlug())
	assert.Equal(t, "management", c.AuthInfo().KeyType)
}

func TestNewClient_InvalidURL(t *testing.T) {
	ctx := context.Background()

	_, err := New(ctx, &Config{BaseURL: "", KeyID: "id", KeySecret: "secret"})
	require.Error(t, err)
}

func TestNewClient_BadCredentials(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	_, err := New(ctx, &Config{BaseURL: srv.URL, KeyID: "bad", KeySecret: "creds"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validating credentials")
}

func TestClient_AuthHeader(t *testing.T) {
	ctx := context.Background()
	var gotAuth string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2/auth" {
			gotAuth = r.Header.Get("Authorization")
			gotContentType = r.Header.Get("Content-Type")
			writeAuthResponse(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	_, err := New(ctx, &Config{BaseURL: srv.URL, KeyID: "hcxmk_testKeyID", KeySecret: "testSecret"})
	require.NoError(t, err)

	assert.Equal(t, "Bearer hcxmk_testKeyID:testSecret", gotAuth)
	assert.Equal(t, jsonapi.MediaType, gotContentType)
}

func TestClient_Retry5xx(t *testing.T) {
	ctx := context.Background()
	var attempts atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_ = c.DeleteAPIKey(ctx, "test-key")
	assert.Equal(t, int32(3), attempts.Load(), "should have retried")
}

func TestClient_NoRetryOn4xx(t *testing.T) {
	ctx := context.Background()
	var attempts atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	})

	err := c.DeleteAPIKey(ctx, "test-key")
	require.Error(t, err)
	assert.Equal(t, int32(1), attempts.Load(), "should not retry on 4xx")
}

func TestClient_RateLimitHeader(t *testing.T) {
	ctx := context.Background()
	var attempts atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Ratelimit", "limit=100, remaining=0, reset=0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := c.DeleteAPIKey(ctx, "test-key")
	require.NoError(t, err)
	assert.Equal(t, int32(2), attempts.Load())
}

func TestClient_5xxExhaustion(t *testing.T) {
	ctx := context.Background()
	var attempts atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	})

	err := c.DeleteAPIKey(ctx, "test-key")
	require.Error(t, err)
	assert.Equal(t, int32(defaultRetryMax+1), attempts.Load(), "should have tried all attempts")
}

func TestClient_RateLimitExhaustion(t *testing.T) {
	ctx := context.Background()
	var attempts atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Ratelimit", "limit=100, remaining=0, reset=0")
		w.WriteHeader(http.StatusTooManyRequests)
	})

	err := c.DeleteAPIKey(ctx, "test-key")
	require.Error(t, err)
	assert.Equal(t, int32(defaultRetryMax+1), attempts.Load(), "should have tried all attempts")
}

func TestClient_ContextCancellation(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	// Slow down retries so cancellation fires first
	c.http.RetryWaitMin = 5 * defaultRetryWaitMax
	c.http.RetryWaitMax = 5 * defaultRetryWaitMax

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	cancel() // cancel immediately

	err := c.DeleteAPIKey(ctx, "test-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestClient_NetworkErrorExhaustion(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, nil)

	c, err := New(ctx, &Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)
	c.http.RetryWaitMin = 0
	c.http.RetryWaitMax = 0

	// Close the server to cause network errors
	srv.Close()

	err = c.DeleteAPIKey(ctx, "test-key")
	require.Error(t, err)
}

func TestClient_PostBodyRetry(t *testing.T) {
	ctx := context.Background()
	var attempts atomic.Int32
	var lastBody string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n := attempts.Add(1)
		body, _ := io.ReadAll(r.Body)
		lastBody = string(body)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", jsonapi.MediaType)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"data": {
				"id": "apikey789",
				"type": "api-keys",
				"attributes": {
					"name": "test-key",
					"key_type": "ingest",
					"secret": "secret123",
					"disabled": false
				}
			}
		}`))
	})

	resp, err := c.CreateAPIKey(ctx, &CreateAPIKeyRequest{
		Name:          "test-key",
		KeyType:       "ingest",
		EnvironmentID: "env1",
		Permissions:   APIKeyPermissions{CreateDatasets: true},
	})
	require.NoError(t, err)
	assert.Equal(t, "apikey789", resp.ID)
	assert.Equal(t, int32(3), attempts.Load(), "should have retried POST")
	assert.NotEmpty(t, lastBody, "body should be present on final retry")
}

func TestClient_Auth(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, nil)

	c, err := New(ctx, &Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)

	assert.Equal(t, "key123", c.AuthInfo().KeyID)
	assert.Equal(t, "test-key", c.AuthInfo().Name)
	assert.Equal(t, "management", c.AuthInfo().KeyType)
	assert.False(t, c.AuthInfo().Disabled)
	assert.Equal(t, []string{"api-keys:write"}, c.AuthInfo().Scopes)
	assert.Equal(t, "my-team", c.TeamSlug())
	assert.Equal(t, "team456", c.AuthInfo().TeamID)
}

func TestClient_ListEnvironments(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2/teams/my-team/environments", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", jsonapi.MediaType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"data": [
				{
					"id": "env1",
					"type": "environments",
					"attributes": {
						"name": "Production",
						"slug": "production"
					}
				},
				{
					"id": "env2",
					"type": "environments",
					"attributes": {
						"name": "Staging",
						"slug": "staging"
					}
				}
			]
		}`))
	})

	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.Len(t, envs, 2)

	assert.Equal(t, "env1", envs[0].ID)
	assert.Equal(t, "Production", envs[0].Name)
	assert.Equal(t, "production", envs[0].Slug)

	assert.Equal(t, "env2", envs[1].ID)
	assert.Equal(t, "Staging", envs[1].Name)
	assert.Equal(t, "staging", envs[1].Slug)
}

func TestClient_CreateAPIKey(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2/teams/my-team/api-keys", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		var reqBody map[string]any
		err = json.Unmarshal(body, &reqBody)
		assert.NoError(t, err)

		data, ok := reqBody["data"].(map[string]any)
		assert.True(t, ok, "expected data to be map[string]any")
		assert.Equal(t, "api-keys", data["type"])

		w.Header().Set("Content-Type", jsonapi.MediaType)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"data": {
				"id": "apikey789",
				"type": "api-keys",
				"attributes": {
					"name": "my-api-key",
					"key_type": "ingest",
					"secret": "hcxik_01abc123secret",
					"disabled": false
				}
			}
		}`))
	})

	resp, err := c.CreateAPIKey(ctx, &CreateAPIKeyRequest{
		Name:          "my-api-key",
		KeyType:       "ingest",
		EnvironmentID: "env1",
		Permissions: APIKeyPermissions{
			CreateDatasets: true,
			SendEvents:     true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "apikey789", resp.ID)
	assert.Equal(t, "my-api-key", resp.Name)
	assert.Equal(t, "ingest", resp.KeyType)
	assert.Equal(t, "hcxik_01abc123secret", resp.Secret)
}

func TestClient_CreateAPIKey_Error(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"insufficient permissions"}]}`))
	})

	_, err := c.CreateAPIKey(ctx, &CreateAPIKeyRequest{
		Name:          "test",
		KeyType:       "ingest",
		EnvironmentID: "env1",
		Permissions:   APIKeyPermissions{CreateDatasets: true},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestClient_DeleteAPIKey(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2/teams/my-team/api-keys/key123", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)
		w.WriteHeader(http.StatusNoContent)
	})

	err := c.DeleteAPIKey(ctx, "key123")
	require.NoError(t, err)
}

func TestClient_DeleteAPIKey_NotFound(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	err := c.DeleteAPIKey(ctx, "nonexistent")
	require.NoError(t, err, "404 should be treated as success")
}
