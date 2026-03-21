package honeycombio

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/jharley/vault-plugin-secrets-honeycombio/internal/client"
)

const (
	backendHelp = `
The Honeycomb.io secrets engine generates dynamic API keys
(Configuration Keys and Ingest Keys) for Honeycomb environments.
`
	walRollbackKind = "honeycomb_key"
)

// Factory returns a configured instance of the backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

const envCacheTTL = 5 * time.Minute

type honeycombBackend struct {
	*framework.Backend
	lock           sync.RWMutex
	client         *client.Client
	envCache       map[string]string
	envCacheExpiry time.Time
}

func backend() *honeycombBackend {
	b := &honeycombBackend{}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"config"},
		},
		Secrets: []*framework.Secret{
			secretHoneycombKey(b),
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathCredentials(b),
			},
			pathRoles(b),
		),
		WALRollback:       b.walRollback,
		WALRollbackMinAge: 1 * time.Minute,
		Invalidate:        b.invalidate,
	}
	return b
}

func (b *honeycombBackend) getClient(ctx context.Context, s logical.Storage) (*client.Client, error) {
	b.lock.RLock()
	if b.client != nil {
		defer b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client != nil {
		return b.client, nil
	}

	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("backend not configured")
	}

	c, err := client.New(ctx, &client.Config{
		BaseURL:   cfg.APIURL,
		KeyID:     cfg.APIKeyID,
		KeySecret: cfg.APIKeySecret,
		Logger:    b.Logger(),
	})
	if err != nil {
		return nil, err
	}

	b.client = c
	return c, nil
}

func (b *honeycombBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
	b.envCache = nil
	b.envCacheExpiry = time.Time{}
}

func (b *honeycombBackend) resolveEnvironmentID(ctx context.Context, s logical.Storage, slug string) (string, error) {
	b.lock.RLock()
	cacheValid := b.envCache != nil && time.Now().Before(b.envCacheExpiry)
	if cacheValid {
		if id, ok := b.envCache[slug]; ok {
			b.lock.RUnlock()
			return id, nil
		}
	}
	b.lock.RUnlock()

	c, err := b.getClient(ctx, s)
	if err != nil {
		return "", err
	}

	envs, err := c.ListEnvironments(ctx)
	if err != nil {
		return "", fmt.Errorf("listing environments: %w", err)
	}

	b.lock.Lock()
	b.envCache = make(map[string]string)
	for _, env := range envs {
		b.envCache[env.Slug] = env.ID
	}
	b.envCacheExpiry = time.Now().Add(envCacheTTL)
	id, ok := b.envCache[slug]
	b.lock.Unlock()

	if !ok {
		return "", fmt.Errorf("environment %q not found", slug)
	}
	return id, nil
}

func (b *honeycombBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data any) error {
	if kind != walRollbackKind {
		return nil
	}

	rawJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}
	var entry walEntry
	if err := json.Unmarshal(rawJSON, &entry); err != nil {
		return err
	}

	if entry.KeyID == "" {
		return nil
	}

	if req == nil {
		return nil
	}

	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("getting client for WAL rollback: %w", err)
	}

	b.Logger().Warn("rolling back orphaned API key", "key_id", entry.KeyID, "role", entry.RoleName)
	return c.DeleteAPIKey(ctx, entry.KeyID)
}

func (b *honeycombBackend) invalidate(_ context.Context, key string) {
	if key == configStoragePath {
		b.reset()
	}
}
