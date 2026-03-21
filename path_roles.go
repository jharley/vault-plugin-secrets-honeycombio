package honeycombio

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const roleStoragePrefix = "role/"

type roleEntry struct {
	Name        string          `json:"name"`
	KeyType     string          `json:"key_type"`
	Environment string          `json:"environment"`
	Permissions rolePermissions `json:"permissions"`
	TTL         time.Duration   `json:"ttl"`
	MaxTTL      time.Duration   `json:"max_ttl"`
}

type rolePermissions struct {
	CreateDatasets     bool `json:"create_datasets"`
	SendEvents         bool `json:"send_events"`
	ManageMarkers      bool `json:"manage_markers"`
	ManageTriggers     bool `json:"manage_triggers"`
	ManageBoards       bool `json:"manage_boards"`
	RunQueries         bool `json:"run_queries"`
	ManageColumns      bool `json:"manage_columns"`
	ManageSLOs         bool `json:"manage_slos"`
	ManageRecipients   bool `json:"manage_recipients"`
	ReadServiceMaps    bool `json:"read_service_maps"`
	VisibleTeamMembers bool `json:"visible_team_members"`
}

func pathRoles(b *honeycombBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
				},
				"key_type": {
					Type:        framework.TypeString,
					Description: "Type of key to create: 'configuration' or 'ingest'",
					Required:    true,
				},
				"environment": {
					Type:        framework.TypeString,
					Description: "Honeycomb environment slug",
					Required:    true,
				},
				"create_datasets": {
					Type:        framework.TypeBool,
					Description: "Permission to create datasets (configuration and ingest)",
				},
				"send_events": {
					Type:        framework.TypeBool,
					Description: "Permission to send events (configuration only)",
				},
				"manage_markers": {
					Type:        framework.TypeBool,
					Description: "Permission to manage markers (configuration only)",
				},
				"manage_triggers": {
					Type:        framework.TypeBool,
					Description: "Permission to manage triggers (configuration only)",
				},
				"manage_boards": {
					Type:        framework.TypeBool,
					Description: "Permission to manage boards (configuration only)",
				},
				"run_queries": {
					Type:        framework.TypeBool,
					Description: "Permission to run queries (configuration only)",
				},
				"manage_columns": {
					Type:        framework.TypeBool,
					Description: "Permission to manage columns (configuration only)",
				},
				"manage_slos": {
					Type:        framework.TypeBool,
					Description: "Permission to manage SLOs (configuration only)",
				},
				"manage_recipients": {
					Type:        framework.TypeBool,
					Description: "Permission to manage recipients (configuration only)",
				},
				"read_service_maps": {
					Type:        framework.TypeBool,
					Description: "Permission to read service maps (configuration only)",
				},
				"visible_team_members": {
					Type:        framework.TypeBool,
					Description: "Permission to view team members (configuration only)",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default TTL for generated keys",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum TTL for generated keys",
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},
			HelpSynopsis:    "Manage roles for Honeycomb key generation",
			HelpDescription: "This path lets you create and manage roles that define templates for Honeycomb API key generation.",
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
				},
			},
			HelpSynopsis:    "List configured roles",
			HelpDescription: "List all configured role names.",
		},
	}
}

func (b *honeycombBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string) //nolint:forcetypeassert
	entry, err := req.Storage.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *honeycombBackend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string) //nolint:forcetypeassert
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"name":                 role.Name,
			"key_type":             role.KeyType,
			"environment":          role.Environment,
			"create_datasets":      role.Permissions.CreateDatasets,
			"send_events":          role.Permissions.SendEvents,
			"manage_markers":       role.Permissions.ManageMarkers,
			"manage_triggers":      role.Permissions.ManageTriggers,
			"manage_boards":        role.Permissions.ManageBoards,
			"run_queries":          role.Permissions.RunQueries,
			"manage_columns":       role.Permissions.ManageColumns,
			"manage_slos":          role.Permissions.ManageSLOs,
			"manage_recipients":    role.Permissions.ManageRecipients,
			"read_service_maps":    role.Permissions.ReadServiceMaps,
			"visible_team_members": role.Permissions.VisibleTeamMembers,
			"ttl":                  int64(role.TTL.Seconds()),
			"max_ttl":              int64(role.MaxTTL.Seconds()),
		},
	}, nil
}

func (b *honeycombBackend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string) //nolint:forcetypeassert

	// For updates, start from the existing role so unset fields are preserved.
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &roleEntry{Name: name}
	}

	// Vault SDK's FieldData.GetOk returns (value, true) only when the field
	// was explicitly provided in the request.
	if v, ok := d.GetOk("key_type"); ok {
		role.KeyType = v.(string) //nolint:forcetypeassert
	}
	if v, ok := d.GetOk("environment"); ok {
		role.Environment = v.(string) //nolint:forcetypeassert
	}

	if role.KeyType != "configuration" && role.KeyType != "ingest" {
		return logical.ErrorResponse("key_type must be 'configuration' or 'ingest'"), nil
	}
	if role.Environment == "" {
		return logical.ErrorResponse("environment is required"), nil
	}

	// Update permissions — only override fields that were explicitly provided.
	permFields := []struct {
		key  string
		dest *bool
	}{
		{"create_datasets", &role.Permissions.CreateDatasets},
		{"send_events", &role.Permissions.SendEvents},
		{"manage_markers", &role.Permissions.ManageMarkers},
		{"manage_triggers", &role.Permissions.ManageTriggers},
		{"manage_boards", &role.Permissions.ManageBoards},
		{"run_queries", &role.Permissions.RunQueries},
		{"manage_columns", &role.Permissions.ManageColumns},
		{"manage_slos", &role.Permissions.ManageSLOs},
		{"manage_recipients", &role.Permissions.ManageRecipients},
		{"read_service_maps", &role.Permissions.ReadServiceMaps},
		{"visible_team_members", &role.Permissions.VisibleTeamMembers},
	}
	for _, pf := range permFields {
		if v, ok := d.GetOk(pf.key); ok {
			*pf.dest = v.(bool) //nolint:forcetypeassert
		}
	}

	// Validate ingest keys can only have create_datasets
	if role.KeyType == "ingest" {
		if role.Permissions.SendEvents || role.Permissions.ManageMarkers || role.Permissions.ManageTriggers ||
			role.Permissions.ManageBoards || role.Permissions.RunQueries || role.Permissions.ManageColumns ||
			role.Permissions.ManageSLOs || role.Permissions.ManageRecipients || role.Permissions.ReadServiceMaps ||
			role.Permissions.VisibleTeamMembers {
			return logical.ErrorResponse("ingest keys can only have 'create_datasets' permission"), nil
		}
	}

	// Validate at least one permission is set
	if !role.Permissions.CreateDatasets && !role.Permissions.SendEvents && !role.Permissions.ManageMarkers &&
		!role.Permissions.ManageTriggers && !role.Permissions.ManageBoards && !role.Permissions.RunQueries &&
		!role.Permissions.ManageColumns && !role.Permissions.ManageSLOs && !role.Permissions.ManageRecipients &&
		!role.Permissions.ReadServiceMaps && !role.Permissions.VisibleTeamMembers {
		return logical.ErrorResponse("at least one permission must be enabled"), nil
	}

	// Vault SDK's TypeDurationSecond returns an int representing seconds.
	if v, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second //nolint:durationcheck,forcetypeassert
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second //nolint:durationcheck,forcetypeassert
	}

	entry, err := logical.StorageEntryJSON(roleStoragePrefix+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *honeycombBackend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string) //nolint:forcetypeassert
	if err := req.Storage.Delete(ctx, roleStoragePrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *honeycombBackend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role roleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}
