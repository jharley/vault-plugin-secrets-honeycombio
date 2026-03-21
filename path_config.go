package honeycombio

import (
	"context"
	"slices"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/jharley/vault-plugin-secrets-honeycombio/internal/client"
)

const (
	configStoragePath = "config"
	defaultAPIURL     = "https://api.honeycomb.io"
)

type honeycombConfig struct {
	APIKeyID     string `json:"api_key_id"`
	APIKeySecret string `json:"api_key_secret"`
	APIURL       string `json:"api_url"`
	TeamSlug     string `json:"team_slug"`
}

func pathConfig(b *honeycombBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"api_key_id": {
				Type:        framework.TypeString,
				Description: "Honeycomb Management API Key ID",
				Required:    true,
			},
			"api_key_secret": {
				Type:        framework.TypeString,
				Description: "Honeycomb Management API Key Secret",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"api_url": {
				Type:        framework.TypeString,
				Description: "Honeycomb API base URL",
				Default:     defaultAPIURL,
			},
		},
		ExistenceCheck: b.pathConfigExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		HelpSynopsis:    "Configure the Honeycomb.io connection",
		HelpDescription: "Configure the management API key used to create and manage Honeycomb API keys.",
	}
}

func (b *honeycombBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

func (b *honeycombBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"api_key_id":     cfg.APIKeyID,
			"api_key_secret": "<redacted>",
			"api_url":        cfg.APIURL,
			"team_slug":      cfg.TeamSlug,
		},
	}, nil
}

func (b *honeycombBackend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Vault SDK's FieldData.Get guarantees the return type matches the FieldSchema.
	apiKeyID := d.Get("api_key_id").(string)         //nolint:forcetypeassert
	apiKeySecret := d.Get("api_key_secret").(string) //nolint:forcetypeassert
	apiURL := d.Get("api_url").(string)              //nolint:forcetypeassert

	if apiKeyID == "" {
		return logical.ErrorResponse("api_key_id is required"), nil
	}
	if apiKeySecret == "" {
		return logical.ErrorResponse("api_key_secret is required"), nil
	}
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	// Validate credentials — New() calls /2/auth to verify the keypair
	// and resolve the team slug.
	c, err := client.New(ctx, &client.Config{
		BaseURL:   apiURL,
		KeyID:     apiKeyID,
		KeySecret: apiKeySecret,
	})
	if err != nil {
		return logical.ErrorResponse("failed to validate credentials: %s", err), nil
	}

	// Verify the key has api-keys:write scope
	if !slices.Contains(c.AuthInfo().Scopes, "api-keys:write") {
		return logical.ErrorResponse("management key must have 'api-keys:write' scope"), nil
	}

	cfg := &honeycombConfig{
		APIKeyID:     apiKeyID,
		APIKeySecret: apiKeySecret,
		APIURL:       apiURL,
		TeamSlug:     c.TeamSlug(),
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()
	b.Logger().Info("config updated", "team", c.TeamSlug())
	return nil, nil
}

func (b *honeycombBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	b.Logger().Info("config deleted")
	return nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*honeycombConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var cfg honeycombConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
