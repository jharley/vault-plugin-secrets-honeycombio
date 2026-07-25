package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	srv := newTestServer(t, handler)
	c, err := New(&Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)
	// Speed up retries for tests
	c.http.RetryWaitMin = 0
	c.http.RetryWaitMax = 0
	return c, srv
}

func TestNewClient(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, nil)

	c, err := New(&Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)
	require.NotNil(t, c)

	auth, err := c.Auth(ctx)
	require.NoError(t, err)
	assert.Equal(t, "my-team", auth.TeamSlug)
	assert.Equal(t, "management", auth.KeyType)
}

func TestNewClient_InvalidURL(t *testing.T) {
	_, err := New(&Config{BaseURL: "", KeyID: "id", KeySecret: "secret"})
	require.Error(t, err)
}

func TestClient_Auth_BadCredentials(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	// Construction succeeds — it performs no I/O. The credentials are only
	// exercised when Auth is called.
	c, err := New(&Config{BaseURL: srv.URL, KeyID: "bad", KeySecret: "creds"})
	require.NoError(t, err)

	_, err = c.Auth(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
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

	c, err := New(&Config{BaseURL: srv.URL, KeyID: "hcxmk_testKeyID", KeySecret: "testSecret"})
	require.NoError(t, err)

	// Construction makes no request, so issue one to observe the headers.
	_, err = c.Auth(ctx)
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

	c, err := New(&Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
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

	c, err := New(&Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)

	auth, err := c.Auth(ctx)
	require.NoError(t, err)

	assert.Equal(t, "key123", auth.KeyID)
	assert.Equal(t, "test-key", auth.Name)
	assert.Equal(t, "management", auth.KeyType)
	assert.False(t, auth.Disabled)
	assert.Equal(t, []string{"api-keys:write"}, auth.Scopes)
	assert.Equal(t, "my-team", auth.TeamSlug)
	assert.Equal(t, "team456", auth.TeamID)
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

func TestClient_ListEnvironments_Pagination(t *testing.T) {
	ctx := context.Background()
	page := 0
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		page++
		w.Header().Set("Content-Type", jsonapi.MediaType)
		w.WriteHeader(http.StatusOK)

		if page == 1 {
			_, _ = w.Write([]byte(`{
				"data": [
					{"id": "env1", "type": "environments", "attributes": {"name": "Production", "slug": "production"}},
					{"id": "env2", "type": "environments", "attributes": {"name": "Staging", "slug": "staging"}}
				],
				"links": {"next": "/2/teams/my-team/environments?page[after]=env2&page[size]=2"}
			}`))
		} else {
			_, _ = w.Write([]byte(`{
				"data": [
					{"id": "env3", "type": "environments", "attributes": {"name": "Development", "slug": "development"}}
				],
				"links": {"next": null}
			}`))
		}
	})

	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.Len(t, envs, 3)

	assert.Equal(t, "env1", envs[0].ID)
	assert.Equal(t, "env2", envs[1].ID)
	assert.Equal(t, "env3", envs[2].ID)
	assert.Equal(t, 2, page, "should have made 2 requests")
}

// TestClient_ListEnvironments_RejectsForeignPaginationLink verifies that a
// server-supplied "next" link cannot redirect an authenticated request to a
// different host. Concatenating the link onto the base URL allows a value such
// as "@evil.example" to reparse the base URL as a userinfo component, sending
// the management key to an attacker-controlled host.
func TestClient_ListEnvironments_RejectsForeignPaginationLink(t *testing.T) {
	var foreignAuth atomic.Value
	foreignAuth.Store("")
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", jsonapi.MediaType)
		_, _ = w.Write([]byte(`{"data": [], "links": {"next": null}}`))
	}))
	t.Cleanup(foreign.Close)
	foreignHost := strings.TrimPrefix(foreign.URL, "http://")

	// wantErr pins each case to the mechanism that actually rejects it, so a
	// passing test cannot be satisfied by an unrelated failure. A link
	// carrying an authority is refused by the origin check; the userinfo form
	// is malformed and never resolves to a host at all.
	tests := map[string]struct{ nextLink, wantErr string }{
		"absolute URL":       {foreign.URL + "/2/teams/my-team/environments", "refusing to follow"},
		"protocol relative":  {"//" + foreignHost + "/2/teams/my-team/environments", "refusing to follow"},
		"userinfo confusion": {"@" + foreignHost + "/2/teams/my-team/environments", "parsing pagination link"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			foreignAuth.Store("")
			// Backstop: an unfixed client can loop when the crafted link
			// resolves back onto the base host.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			t.Cleanup(cancel)
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", jsonapi.MediaType)
				_, _ = w.Write([]byte(`{"data": [], "links": {"next": ` + strconv.Quote(tc.nextLink) + `}}`))
			})

			_, err := c.ListEnvironments(ctx)
			assert.ErrorContains(t, err, tc.wantErr)
			assert.Empty(t, foreignAuth.Load(),
				"credentials must never be sent to a host other than the configured API")
		})
	}
}

// TestClient_ListEnvironments_BoundsPageCount verifies that a server which
// always advertises another page cannot hold the request in an unbounded fetch
// loop.
// TestClient_ListEnvironments_PreservesBasePathPrefix verifies that following
// a pagination link keeps any path prefix in the configured API URL. Resolving
// an absolute-path link as a URL reference would discard it, breaking setups
// that reach Honeycomb through a proxy mounted under a subpath.
func TestClient_ListEnvironments_PreservesBasePathPrefix(t *testing.T) {
	ctx := context.Background()
	var paths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", jsonapi.MediaType)
		switch {
		case strings.HasSuffix(r.URL.Path, "/2/auth"):
			_, _ = w.Write([]byte(authResponse))
		case r.URL.Query().Get("page") == "":
			_, _ = w.Write([]byte(`{
				"data": [{"id": "env1", "type": "environments", "attributes": {"name": "P", "slug": "production"}}],
				"links": {"next": "/2/teams/my-team/environments?page=2"}
			}`))
		default:
			_, _ = w.Write([]byte(`{
				"data": [{"id": "env2", "type": "environments", "attributes": {"name": "S", "slug": "staging"}}],
				"links": {"next": null}
			}`))
		}
	}))
	t.Cleanup(srv.Close)

	c, err := New(&Config{BaseURL: srv.URL + "/honeycomb", KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)

	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	assert.Len(t, envs, 2, "should follow the next link successfully")

	for _, p := range paths {
		assert.True(t, strings.HasPrefix(p, "/honeycomb/"),
			"every request must keep the configured path prefix, got %q", p)
	}
}

// TestClient_RefusesRedirectOffOrigin verifies that a redirect cannot move an
// authenticated request to another origin. Go only strips the Authorization
// header across domains, so a redirect to a different port, a subdomain, or an
// https->http downgrade of the same host would otherwise carry the management
// key along with it.
func TestClient_RefusesRedirectOffOrigin(t *testing.T) {
	ctx := context.Background()

	var foreignAuth atomic.Value
	foreignAuth.Store("")
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", jsonapi.MediaType)
		_, _ = w.Write([]byte(`{"data": [], "links": {"next": null}}`))
	}))
	t.Cleanup(foreign.Close)

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+r.URL.Path, http.StatusFound)
	})

	_, err := c.ListEnvironments(ctx)
	assert.Error(t, err, "a redirect off the configured origin should fail")
	assert.Empty(t, foreignAuth.Load(),
		"credentials must not follow a redirect to another origin")
}

func TestClient_ListEnvironments_BoundsPageCount(t *testing.T) {
	// The deadline is a backstop only: a correct implementation stops on its
	// own after maxPaginationPages, long before this fires.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	var pages atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		pages.Add(1)
		w.Header().Set("Content-Type", jsonapi.MediaType)
		_, _ = w.Write([]byte(`{
			"data": [{"id": "env1", "type": "environments", "attributes": {"name": "E", "slug": "e"}}],
			"links": {"next": "/2/teams/my-team/environments?page=next"}
		}`))
	})

	_, err := c.ListEnvironments(ctx)
	assert.ErrorContains(t, err, "exceeded",
		"should stop on the page cap, not for an incidental reason")
	assert.NotErrorIs(t, err, context.DeadlineExceeded,
		"should terminate on its own, not by exhausting the request deadline")
	assert.Less(t, pages.Load(), int32(1000), "page fetches should be bounded")
}

// TestClient_ListEnvironments_RejectsOversizedResponse verifies that an
// oversized response body is rejected rather than read entirely into memory.
func TestClient_ListEnvironments_RejectsOversizedResponse(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", jsonapi.MediaType)
		_, _ = w.Write([]byte(`{"data": [], "links": {"next": null}, "pad": "`))
		chunk := bytes.Repeat([]byte("A"), 1<<20)
		for range (maxResponseBodySize >> 20) + 2 {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte(`"}`))
	})

	_, err := c.ListEnvironments(ctx)
	require.Error(t, err, "oversized response bodies should be rejected")
	assert.Contains(t, err.Error(), "too large")
}

func TestClient_RateLimitBackoff_CapsServerSuppliedReset(t *testing.T) {
	c := &Client{}
	minWait, maxWait := 500*time.Millisecond, 30*time.Second

	tests := map[string]string{
		"one day":            "reset=86400",
		"implausibly large":  "reset=999999999",
		"overflows int64 ns": "reset=99999999999999",
	}

	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
			resp.Header.Set("Ratelimit", "limit=100, remaining=0, "+header)

			got := c.rateLimitBackoff(minWait, maxWait, resp)
			assert.Positive(t, got, "backoff must never be zero or negative")
			assert.LessOrEqual(t, got, 2*maxWait, "backoff must stay bounded by maxWait plus jitter")
		})
	}
}

// TestClient_RateLimitBackoff_StaysProportionalToReset verifies that jitter
// scales with the wait rather than being drawn across the whole retry range.
// A server asking for a one second window should get roughly one second, not
// a wait dominated by jitter sized against maxWait.
func TestClient_RateLimitBackoff_StaysProportionalToReset(t *testing.T) {
	c := &Client{}
	minWait, maxWait := 500*time.Millisecond, 30*time.Second

	for _, want := range []time.Duration{time.Second, 2 * time.Second, 10 * time.Second} {
		t.Run(want.String(), func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
			resp.Header.Set("Ratelimit", "limit=100, remaining=0, reset="+strconv.Itoa(int(want.Seconds())))

			// Jitter is random, so sample repeatedly rather than trusting one draw.
			for range 20 {
				got := c.rateLimitBackoff(minWait, maxWait, resp)
				assert.GreaterOrEqual(t, got, want, "must wait at least the window the server asked for")
				assert.Less(t, got, 2*want, "jitter must not inflate a short window")
			}
		})
	}
}

func TestClient_RateLimitBackoff_HonoursShortReset(t *testing.T) {
	c := &Client{}
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
	resp.Header.Set("Ratelimit", "limit=100, remaining=0, reset=5")

	got := c.rateLimitBackoff(500*time.Millisecond, 30*time.Second, resp)
	assert.GreaterOrEqual(t, got, 5*time.Second, "a reset within bounds should still be honoured")
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

// TestNewClient_MakesNoRequest verifies that constructing a client performs no
// network I/O. An eager /2/auth round-trip in the constructor is unbounded
// blocking work on every cold path, and costs an extra request per revocation.
func TestNewClient_MakesNoRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeAuthResponse(w)
	}))
	t.Cleanup(srv.Close)

	c, err := New(&Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Zero(t, calls.Load(), "construction must not call the API")
}

// TestClient_ResolvesTeamSlugOnceLazily verifies the slug is fetched on first
// use when it was not seeded, then cached for subsequent calls.
func TestClient_ResolvesTeamSlugOnceLazily(t *testing.T) {
	ctx := context.Background()
	var authCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2/auth" {
			authCalls.Add(1)
			writeAuthResponse(w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	c, err := New(&Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)

	require.NoError(t, c.DeleteAPIKey(ctx, "key1"))
	require.NoError(t, c.DeleteAPIKey(ctx, "key2"))
	assert.Equal(t, int32(1), authCalls.Load(), "team slug should be resolved once and cached")
}

// TestClient_DoesNotCacheAuthFailure verifies a transient /2/auth failure does
// not poison the client for later calls.
func TestClient_DoesNotCacheAuthFailure(t *testing.T) {
	ctx := context.Background()
	var failAuth atomic.Bool
	failAuth.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/2/auth" {
			if failAuth.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writeAuthResponse(w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	c, err := New(&Config{BaseURL: srv.URL, KeyID: "id", KeySecret: "secret"})
	require.NoError(t, err)
	c.SetRetryWait(0, 0)

	assert.Error(t, c.DeleteAPIKey(ctx, "key1"), "should fail while /2/auth is down")

	failAuth.Store(false)
	assert.NoError(t, c.DeleteAPIKey(ctx, "key2"), "should recover once /2/auth works")
}
