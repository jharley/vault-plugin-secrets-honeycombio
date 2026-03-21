package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/jsonapi"
)

const (
	defaultRetryMax     = 3
	defaultRetryWaitMin = 500 * time.Millisecond
	defaultRetryWaitMax = 30 * time.Second

	// maxErrorBodySize is the maximum number of bytes read from error
	// response bodies for inclusion in error messages.
	maxErrorBodySize = 8192
)

// Config holds the connection parameters for a Honeycomb API client.
type Config struct {
	// BaseURL is the Honeycomb API base URL (e.g., "https://api.honeycomb.io").
	BaseURL string

	// KeyID is the Management API Key ID.
	KeyID string

	// KeySecret is the Management API Key Secret.
	KeySecret string

	// Logger is an optional hclog.Logger for HTTP retry diagnostics.
	// If nil, a no-op logger is used.
	Logger hclog.Logger
}

// Client is a minimal Honeycomb v2 Management API client.
type Client struct {
	baseURL   string
	keyID     string
	keySecret string
	teamSlug  string
	authInfo  *AuthResponse
	http      *retryablehttp.Client
}

// New creates a new Honeycomb API client. It validates the credentials by
// calling /2/auth and resolves the team slug for subsequent API calls.
func New(ctx context.Context, cfg *Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}
	if cfg.KeyID == "" {
		return nil, fmt.Errorf("KeyID is required")
	}
	if cfg.KeySecret == "" {
		return nil, fmt.Errorf("KeySecret is required")
	}

	c := &Client{
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		keyID:     cfg.KeyID,
		keySecret: cfg.KeySecret,
	}
	logger := cfg.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	c.http = &retryablehttp.Client{
		Backoff:      c.retryBackoff,
		CheckRetry:   c.retryCheck,
		ErrorHandler: retryablehttp.PassthroughErrorHandler,
		HTTPClient:   &http.Client{Timeout: 30 * time.Second},
		Logger:       logger.Named("honeycomb.http"),
		RetryWaitMin: defaultRetryWaitMin,
		RetryWaitMax: defaultRetryWaitMax,
		RetryMax:     defaultRetryMax,
	}

	auth, err := c.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("validating credentials: %w", err)
	}
	c.teamSlug = auth.TeamSlug
	c.authInfo = auth

	return c, nil
}

// TeamSlug returns the team slug this client is configured for.
func (c *Client) TeamSlug() string {
	return c.teamSlug
}

// AuthInfo returns the auth metadata retrieved during client initialization.
func (c *Client) AuthInfo() *AuthResponse {
	return c.authInfo
}

// SetRetryWait configures the retry wait bounds. Intended for testing.
func (c *Client) SetRetryWait(minWait, maxWait time.Duration) {
	c.http.RetryWaitMin = minWait
	c.http.RetryWaitMax = maxWait
}

// do executes an HTTP request with auth headers. Retry and rate-limit handling
// are provided by the underlying retryablehttp.Client.
func (c *Client) do(req *retryablehttp.Request) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s:%s", c.keyID, c.keySecret))
	req.Header.Set("Content-Type", jsonapi.MediaType)
	return c.http.Do(req)
}

// retryCheck determines whether a request should be retried.
func (c *Client) retryCheck(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		return true, err
	}
	if resp != nil {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return true, nil
		}
	}
	return false, nil
}

// retryBackoff calculates the backoff duration for a retry attempt.
// For 429 responses, it uses the Ratelimit or Retry-After headers.
// For all other retryable responses, it uses linear backoff with jitter.
func (c *Client) retryBackoff(minWait, maxWait time.Duration, attemptNum int, resp *http.Response) time.Duration {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		return c.rateLimitBackoff(minWait, maxWait, resp)
	}
	return retryablehttp.LinearJitterBackoff(minWait, maxWait, attemptNum, resp)
}

// rateLimitBackoff extracts the backoff duration from rate-limit headers.
// Parses the Ratelimit header (format: "limit=X, remaining=Y, reset=Z")
// and falls back to Retry-After header. The returned duration may exceed
// maxWait when the server's reset window is large — this is intentional
// to respect the server's rate-limit window.
func (c *Client) rateLimitBackoff(minWait, maxWait time.Duration, resp *http.Response) time.Duration {
	var jitter time.Duration
	if maxWait > minWait {
		jitter = time.Duration(rand.Int64N(int64(maxWait - minWait)))
	}

	var reset time.Duration
	if rl := resp.Header.Get("Ratelimit"); rl != "" {
		for _, part := range strings.Split(rl, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "reset=") {
				if seconds, err := strconv.Atoi(strings.TrimPrefix(part, "reset=")); err == nil && seconds > 0 {
					reset = time.Duration(seconds) * time.Second
				}
			}
		}
	}

	if reset == 0 {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, err := strconv.Atoi(ra); err == nil && seconds > 0 {
				reset = time.Duration(seconds) * time.Second
			} else if t, err := http.ParseTime(ra); err == nil {
				if d := time.Until(t); d > 0 {
					reset = d
				}
			}
		}
	}

	if reset > minWait {
		minWait = reset
	}
	return minWait + jitter
}

// AuthResponse contains metadata about the management API key.
type AuthResponse struct {
	KeyID    string
	Name     string
	KeyType  string
	Disabled bool
	Scopes   []string
	TeamSlug string
	TeamID   string
}

// APIKeyPermissions defines the permission set for an API key.
// Configuration-only permissions use omitempty so they are omitted for ingest
// keys, which the Honeycomb API rejects if present.
type APIKeyPermissions struct {
	CreateDatasets     bool `json:"create_datasets"`
	SendEvents         bool `json:"send_events,omitempty"`
	ManageMarkers      bool `json:"manage_markers,omitempty"`
	ManageTriggers     bool `json:"manage_triggers,omitempty"`
	ManageBoards       bool `json:"manage_boards,omitempty"`
	RunQueries         bool `json:"run_queries,omitempty"`
	ManageColumns      bool `json:"manage_columns,omitempty"`
	ManageSLOs         bool `json:"manage_slos,omitempty"`
	ManageRecipients   bool `json:"manage_recipients,omitempty"`
	ReadServiceMaps    bool `json:"read_service_maps,omitempty"`
	VisibleTeamMembers bool `json:"visible_team_members,omitempty"`
}

// CreateAPIKeyRequest is the input for creating a new API key.
type CreateAPIKeyRequest struct {
	Name          string
	KeyType       string
	EnvironmentID string
	Permissions   APIKeyPermissions
}

// APIKeyResponse is the result of creating an API key.
type APIKeyResponse struct {
	ID      string
	Name    string
	KeyType string
	Secret  string
}

// JSON:API model structs for hashicorp/jsonapi serialization.

type authKey struct {
	ID       string   `jsonapi:"primary,api-keys"`
	Name     string   `jsonapi:"attr,name"`
	KeyType  string   `jsonapi:"attr,key_type"`
	Disabled bool     `jsonapi:"attr,disabled"`
	Scopes   []string `jsonapi:"attr,scopes"`
	Team     *team    `jsonapi:"relation,team"`
}

type team struct {
	ID   string `jsonapi:"primary,teams"`
	Name string `jsonapi:"attr,name"`
	Slug string `jsonapi:"attr,slug"`
}

// Environment represents a Honeycomb environment.
type Environment struct {
	ID   string `jsonapi:"primary,environments"`
	Name string `jsonapi:"attr,name"`
	Slug string `jsonapi:"attr,slug"`
}

type paginationLinks struct {
	Next string `json:"next"`
}

type apiKey struct {
	ID          string             `jsonapi:"primary,api-keys"`
	Name        string             `jsonapi:"attr,name"`
	KeyType     string             `jsonapi:"attr,key_type"`
	Secret      string             `jsonapi:"attr,secret,omitempty"`
	Disabled    bool               `jsonapi:"attr,disabled"`
	Permissions *APIKeyPermissions `jsonapi:"attr,permissions,omitempty"`
	Environment *Environment       `jsonapi:"relation,environment"`
}

// Auth validates the management API key and returns metadata about it.
func (c *Client) Auth(ctx context.Context) (*AuthResponse, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/2/auth", nil)
	if err != nil {
		return nil, fmt.Errorf("creating auth request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return nil, fmt.Errorf("auth request returned status %d: %s", resp.StatusCode, string(body))
	}

	result := new(authKey)
	if err := jsonapi.UnmarshalPayload(resp.Body, result); err != nil {
		return nil, fmt.Errorf("decoding auth response: %w", err)
	}

	if result.Team == nil {
		return nil, fmt.Errorf("team not found in auth response")
	}

	return &AuthResponse{
		KeyID:    result.ID,
		Name:     result.Name,
		KeyType:  result.KeyType,
		Disabled: result.Disabled,
		Scopes:   result.Scopes,
		TeamSlug: result.Team.Slug,
		TeamID:   result.Team.ID,
	}, nil
}

// ListEnvironments returns all environments for the given team.
// Follows cursor-based pagination to retrieve all pages.
func (c *Client) ListEnvironments(ctx context.Context) ([]Environment, error) {
	var allEnvs []Environment
	endpoint := c.baseURL + "/2/teams/" + c.teamSlug + "/environments"

	for {
		req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("creating list environments request: %w", err)
		}

		resp, err := c.do(req)
		if err != nil {
			return nil, fmt.Errorf("list environments request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
			resp.Body.Close()
			return nil, fmt.Errorf("list environments returned status %d: %s", resp.StatusCode, string(body))
		}

		// Read the full body so we can decode both data and pagination links.
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading environments response: %w", err)
		}

		items, err := jsonapi.UnmarshalManyPayload(bytes.NewReader(body), reflect.TypeOf(new(Environment)))
		if err != nil {
			return nil, fmt.Errorf("decoding environments response: %w", err)
		}

		for _, item := range items {
			allEnvs = append(allEnvs, *item.(*Environment)) //nolint:forcetypeassert // type guaranteed by UnmarshalManyPayload
		}

		// Check for next page via the links object.
		var page struct {
			Links *paginationLinks `json:"links"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decoding pagination links: %w", err)
		}

		if page.Links == nil || page.Links.Next == "" {
			break
		}
		endpoint = c.baseURL + page.Links.Next
	}

	return allEnvs, nil
}

// CreateAPIKey creates a new API key in the given team.
func (c *Client) CreateAPIKey(ctx context.Context, input *CreateAPIKeyRequest) (*APIKeyResponse, error) {
	key := &apiKey{
		Name:        input.Name,
		KeyType:     input.KeyType,
		Permissions: &input.Permissions,
		Environment: &Environment{ID: input.EnvironmentID},
	}

	var buf bytes.Buffer
	if err := jsonapi.MarshalPayload(&buf, key); err != nil {
		return nil, fmt.Errorf("marshaling create API key request: %w", err)
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/2/teams/"+c.teamSlug+"/api-keys", &buf)
	if err != nil {
		return nil, fmt.Errorf("creating API key request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("create API key request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return nil, fmt.Errorf("create API key returned status %d: %s", resp.StatusCode, string(body))
	}

	result := new(apiKey)
	if err := jsonapi.UnmarshalPayload(resp.Body, result); err != nil {
		return nil, fmt.Errorf("decoding create API key response: %w", err)
	}

	return &APIKeyResponse{
		ID:      result.ID,
		Name:    result.Name,
		KeyType: result.KeyType,
		Secret:  result.Secret,
	}, nil
}

// DeleteAPIKey deletes an API key. Treats 404 as success (idempotent).
func (c *Client) DeleteAPIKey(ctx context.Context, keyID string) error {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/2/teams/"+c.teamSlug+"/api-keys/"+keyID, nil)
	if err != nil {
		return fmt.Errorf("creating delete API key request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("delete API key request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return fmt.Errorf("delete API key returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
