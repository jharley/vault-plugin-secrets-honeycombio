package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

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

	// maxResponseBodySize bounds how much of a successful response body is
	// buffered. A team with tens of thousands of environments stays well
	// under this; anything larger is treated as a malformed or hostile
	// response rather than being read into memory.
	maxResponseBodySize = 10 << 20 // 10 MiB

	// maxPaginationPages bounds how many pages a single paginated call will
	// follow, so a server that always advertises another page cannot hold the
	// request in an unbounded fetch loop.
	maxPaginationPages = 100

	// maxRateLimitReset bounds the reset window accepted from a server before
	// it is converted to a Duration, so an absurd value cannot overflow the
	// int64 nanosecond representation.
	maxRateLimitReset = 24 * time.Hour

	// maxRedirects bounds redirect chains within the configured origin.
	maxRedirects = 5

	// backoffJitterDivisor sets how much jitter is added to a rate-limit
	// backoff, as a fraction of the wait itself (wait/4, so up to +25%).
	backoffJitterDivisor = 4

	// maxErrorDetailLength bounds how much server-supplied text is carried in
	// an APIError. The detail reaches Vault lease warnings and the audit log,
	// so it is kept short rather than echoing an arbitrary response body.
	maxErrorDetailLength = 512
)

// errRedirectRefused marks a redirect rejected by policy. It is deterministic,
// so retrying cannot help.
var errRedirectRefused = errors.New("refusing to follow redirect")

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
	base      *url.URL
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

	trimmed := strings.TrimRight(cfg.BaseURL, "/")
	base, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parsing BaseURL: %w", err)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("BaseURL %q has no host", cfg.BaseURL)
	}

	c := &Client{
		baseURL:   trimmed,
		base:      base,
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
		HTTPClient:   &http.Client{Timeout: 30 * time.Second, CheckRedirect: c.checkRedirect},
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
	if errors.Is(err, errRedirectRefused) {
		return false, err
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
// and falls back to Retry-After header.
//
// The server's reset window is honoured only up to maxWait. Waiting longer
// than that inside a single request is pointless — the caller's context
// expires first — and an unbounded value lets a hostile or malfunctioning
// server stall the request for as long as it likes.
func (c *Client) rateLimitBackoff(minWait, maxWait time.Duration, resp *http.Response) time.Duration {
	var reset time.Duration
	if rl := resp.Header.Get("Ratelimit"); rl != "" {
		for _, part := range strings.Split(rl, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "reset=") {
				if seconds, err := strconv.Atoi(strings.TrimPrefix(part, "reset=")); err == nil && seconds > 0 {
					reset = secondsToDuration(seconds)
				}
			}
		}
	}

	if reset == 0 {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, err := strconv.Atoi(ra); err == nil && seconds > 0 {
				reset = secondsToDuration(seconds)
			} else if t, err := http.ParseTime(ra); err == nil {
				if d := time.Until(t); d > 0 {
					reset = min(d, maxRateLimitReset)
				}
			}
		}
	}

	wait := minWait
	if reset > wait {
		wait = reset
	}

	// Jitter spreads out clients that would otherwise all retry the instant
	// the window closes. It is a fraction of the wait rather than a draw
	// across the whole retry range, so a short window stays short — drawing
	// against maxWait turned a one second reset into a ~16 second wait.
	if spread := int64(wait) / backoffJitterDivisor; spread > 0 {
		wait += time.Duration(rand.Int64N(spread))
	}

	return min(wait, maxWait)
}

// secondsToDuration converts a server-supplied second count to a Duration,
// clamping first so an implausibly large value cannot overflow int64
// nanoseconds and wrap to a negative or nonsensical wait.
func secondsToDuration(seconds int) time.Duration {
	if seconds > int(maxRateLimitReset/time.Second) {
		return maxRateLimitReset
	}
	return time.Duration(seconds) * time.Second
}

// APIError is returned for a non-success HTTP response. Callers can inspect
// StatusCode with errors.As to decide whether a failure is worth retrying.
type APIError struct {
	StatusCode int
	Detail     string
}

func (e *APIError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("status %d", e.StatusCode)
	}
	return fmt.Sprintf("status %d: %s", e.StatusCode, e.Detail)
}

// Retryable reports whether the failure may succeed on a later attempt.
// Server-side failures, timeouts and rate limiting are transient; other 4xx
// responses indicate a request that will fail identically every time.
func (e *APIError) Retryable() bool {
	switch e.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	default:
		return e.StatusCode >= 500
	}
}

// apiError parses a JSON:API error response and returns an *APIError.
// Falls back to the raw body if the response is not valid JSON:API.
func apiError(resp *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
	if err != nil || len(body) == 0 {
		return &APIError{StatusCode: resp.StatusCode}
	}

	var payload jsonapi.ErrorsPayload
	if err := json.Unmarshal(body, &payload); err == nil && len(payload.Errors) > 0 {
		messages := make([]string, len(payload.Errors))
		for i, e := range payload.Errors {
			if e.Detail != "" {
				messages[i] = e.Detail
			} else {
				messages[i] = e.Title
			}
		}
		return &APIError{StatusCode: resp.StatusCode, Detail: truncateDetail(strings.Join(messages, "; "))}
	}

	return &APIError{StatusCode: resp.StatusCode, Detail: truncateDetail(string(body))}
}

// truncateDetail bounds server-supplied error text. It surfaces in Vault lease
// warnings and the audit log, so an arbitrary response body is not echoed
// wholesale.
func truncateDetail(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))

	if len(s) > maxErrorDetailLength {
		return s[:maxErrorDetailLength] + "… (truncated)"
	}
	return s
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
		return nil, fmt.Errorf("auth request: %w", apiError(resp))
	}

	body, err := readLimited(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading auth response: %w", err)
	}

	result := new(authKey)
	if err := jsonapi.UnmarshalPayload(bytes.NewReader(body), result); err != nil {
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
	endpoint := c.baseURL + "/2/teams/" + url.PathEscape(c.teamSlug) + "/environments"

	for page := 0; ; page++ {
		if page >= maxPaginationPages {
			return nil, fmt.Errorf("listing environments exceeded %d pages", maxPaginationPages)
		}

		req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("creating list environments request: %w", err)
		}

		resp, err := c.do(req)
		if err != nil {
			return nil, fmt.Errorf("list environments request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			err := fmt.Errorf("list environments: %w", apiError(resp))
			resp.Body.Close()
			return nil, err
		}

		// Read the full body so we can decode both data and pagination links.
		body, err := readLimited(resp.Body)
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
		var links struct {
			Links *paginationLinks `json:"links"`
		}
		if err := json.Unmarshal(body, &links); err != nil {
			return nil, fmt.Errorf("decoding pagination links: %w", err)
		}

		if links.Links == nil || links.Links.Next == "" {
			break
		}

		next, err := c.resolveAPIURL(links.Links.Next)
		if err != nil {
			return nil, err
		}
		endpoint = next
	}

	return allEnvs, nil
}

// resolveAPIURL turns a server-supplied link into a request URL, refusing
// anything that would leave the configured API origin. Without this check a
// link such as "@evil.example/path" reparses the base URL as a userinfo
// component, sending the management key to another host.
func (c *Client) resolveAPIURL(link string) (string, error) {
	ref, err := url.Parse(link)
	if err != nil {
		return "", fmt.Errorf("parsing pagination link %q: %w", link, err)
	}

	// A link carrying its own scheme or authority must match the configured
	// origin exactly.
	if ref.Scheme != "" || ref.Host != "" {
		if ref.Scheme != c.base.Scheme || ref.Host != c.base.Host {
			return "", fmt.Errorf("refusing to follow pagination link %q: resolves to %s://%s, expected %s://%s",
				link, ref.Scheme, ref.Host, c.base.Scheme, c.base.Host)
		}
		ref.User = nil // never echo credentials from a server-supplied link
		return ref.String(), nil
	}

	// A path-only link is re-anchored on the configured base URL rather than
	// resolved as a URL reference, so that a base with a path prefix (an API
	// reached through a proxy mounted under a subpath) keeps that prefix.
	return c.baseURL + "/" + strings.TrimPrefix(ref.String(), "/"), nil
}

// checkRedirect refuses any redirect that leaves the configured API origin.
// Go strips the Authorization header only across domains, so a redirect to a
// different port, to a subdomain, or downgrading https to http on the same
// host would otherwise carry the management key along with it.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", errRedirectRefused, maxRedirects)
	}
	if req.URL.Scheme != c.base.Scheme || req.URL.Host != c.base.Host {
		return fmt.Errorf("%w to %s://%s, expected %s://%s",
			errRedirectRefused, req.URL.Scheme, req.URL.Host, c.base.Scheme, c.base.Host)
	}
	return nil
}

// readLimited reads r into memory, refusing bodies larger than
// maxResponseBodySize so a hostile or malfunctioning server cannot exhaust
// process memory.
func readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxResponseBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBodySize {
		return nil, fmt.Errorf("response body too large (exceeds %d bytes)", maxResponseBodySize)
	}
	return body, nil
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

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/2/teams/"+url.PathEscape(c.teamSlug)+"/api-keys", &buf)
	if err != nil {
		return nil, fmt.Errorf("creating API key request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("create API key request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("create API key: %w", apiError(resp))
	}

	body, err := readLimited(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading create API key response: %w", err)
	}

	result := new(apiKey)
	if err := jsonapi.UnmarshalPayload(bytes.NewReader(body), result); err != nil {
		return nil, fmt.Errorf("decoding create API key response: %w", err)
	}
	if result.ID == "" {
		return nil, fmt.Errorf("create API key: response contained no key ID")
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
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/2/teams/"+url.PathEscape(c.teamSlug)+"/api-keys/"+url.PathEscape(keyID), nil)
	if err != nil {
		return fmt.Errorf("creating delete API key request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("delete API key request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("delete API key: %w", apiError(resp))
	}

	return nil
}
