# Terraform SSO Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add first-class Terraform CRUD resources for Neuwerk Google, GitHub, and generic OIDC SSO providers, including secret-preserving refresh behavior, UUID imports, focused unit coverage, and minimal README documentation.

**Architecture:** Keep the Terraform provider surface explicit by adding three separate resource types backed by one shared SSO implementation layer. Put request/response wiring in the shared API client, centralize schema/state mapping and secret preservation in shared resource helpers, and keep each provider-kind resource as a thin wrapper that fixes the kind and any schema differences.

**Tech Stack:** Go, Terraform Plugin Framework, `httptest`, Neuwerk HTTP API client helpers, Markdown README docs

---

## File Map

- Modify: `terraform-provider-neuwerk/internal/provider/client.go`
  Responsibility: add SSO provider API request/response structs plus CRUD client methods for `/api/v1/settings/sso/providers`.
- Modify: `terraform-provider-neuwerk/internal/provider/provider.go`
  Responsibility: register the three new SSO provider resources in the provider resource list.
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go`
  Responsibility: define shared Terraform models, schema builders, import parsing, set normalization, request builders, secret-preserving state mapping, and the shared CRUD implementation used by all SSO resources.
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_google.go`
  Responsibility: expose `neuwerk_sso_provider_google` as a thin wrapper over the shared implementation with fixed kind and Google schema defaults.
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_github.go`
  Responsibility: expose `neuwerk_sso_provider_github` as a thin wrapper over the shared implementation with fixed kind and GitHub schema defaults.
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_generic_oidc.go`
  Responsibility: expose `neuwerk_sso_provider_generic_oidc` as a thin wrapper over the shared implementation with fixed kind and required endpoint attributes.
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go`
  Responsibility: cover schema shape, import parsing, state convergence, kind-mismatch behavior, CRUD request shaping, and provider resource registration.
- Modify: `terraform-provider-neuwerk/README.md`
  Responsibility: document the new resources, add concise examples for each provider kind, and call out import and `client_secret` lifecycle semantics.

## Preconditions

- Use the approved spec at `docs/superpowers/specs/2026-03-22-terraform-sso-providers-design.md` as the source of truth.
- Work from the dedicated worktree branch at `/home/moritz/dev/neuwerk-rs/firewall/.worktrees/terraform-service-accounts`.
- Run Terraform provider tests from `terraform-provider-neuwerk/`.

### Task 1: Add Shared SSO State and Schema Helpers

**Files:**
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go`
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go`

- [ ] **Step 1: Verify no SSO resource implementation exists yet**

Run:

```bash
cd terraform-provider-neuwerk
rg -n "sso_provider|SsoProvider" internal/provider
```

Expected: no matches for an existing Terraform SSO resource implementation.

- [ ] **Step 2: Write failing shared-helper tests**

Add these tests to `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go`:

```go
func TestSsoProviderStateFromAPIPreservesSecretAndNormalizesSets(t *testing.T) {
	t.Parallel()

	prior := ssoProviderResourceModel{
		ClientSecret: types.StringValue("top-secret"),
		Scopes:       types.SetValueMust(types.StringType, []attr.Value{types.StringValue("openid")}),
	}
	record := &apiSsoProvider{
		ID:                     "prov-1",
		Name:                   "Corp Google",
		Kind:                   "google",
		ClientID:               "client-1",
		ClientSecretConfigured: true,
		Scopes:                 []string{"openid", "email"},
	}

	state := ssoProviderStateFromAPI(prior, record)

	if state.ClientSecret.ValueString() != "top-secret" {
		t.Fatalf("expected prior secret to be preserved")
	}
	if state.Scopes.IsNull() {
		t.Fatalf("expected scopes set to be populated")
	}
}

func TestParseSsoProviderImportIDRejectsBlank(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	if _, ok := parseSsoProviderImportID("   ", &diags); ok {
		t.Fatalf("expected blank import id to fail")
	}
	if !diags.HasError() {
		t.Fatalf("expected diagnostics")
	}
}
```

- [ ] **Step 3: Run the targeted tests and confirm they fail**

Run:

```bash
cd terraform-provider-neuwerk
go test ./internal/provider -run 'TestSsoProviderStateFromAPIPreservesSecretAndNormalizesSets|TestParseSsoProviderImportIDRejectsBlank' -count=1
```

Expected: build fails with undefined `ssoProviderResourceModel`, `apiSsoProvider`, `ssoProviderStateFromAPI`, and `parseSsoProviderImportID`.

- [ ] **Step 4: Implement the shared SSO model, set helpers, and import parser**

Create `terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go` with shared pieces like:

```go
type ssoProviderKindConfig struct {
	resourceSuffix           string
	apiKind                  string
	requireExplicitEndpoints bool
}

type ssoProviderResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	DisplayOrder         types.Int64  `tfsdk:"display_order"`
	IssuerURL            types.String `tfsdk:"issuer_url"`
	ClientID             types.String `tfsdk:"client_id"`
	ClientSecret         types.String `tfsdk:"client_secret"`
	Scopes               types.Set    `tfsdk:"scopes"`
	PKCERequired         types.Bool   `tfsdk:"pkce_required"`
	SubjectClaim         types.String `tfsdk:"subject_claim"`
	EmailClaim           types.String `tfsdk:"email_claim"`
	GroupsClaim          types.String `tfsdk:"groups_claim"`
	DefaultRole          types.String `tfsdk:"default_role"`
	AdminSubjects        types.Set    `tfsdk:"admin_subjects"`
	AdminGroups          types.Set    `tfsdk:"admin_groups"`
	AdminEmailDomains    types.Set    `tfsdk:"admin_email_domains"`
	ReadonlySubjects     types.Set    `tfsdk:"readonly_subjects"`
	ReadonlyGroups       types.Set    `tfsdk:"readonly_groups"`
	ReadonlyEmailDomains types.Set    `tfsdk:"readonly_email_domains"`
	AllowedEmailDomains  types.Set    `tfsdk:"allowed_email_domains"`
	AuthorizationURL     types.String `tfsdk:"authorization_url"`
	TokenURL             types.String `tfsdk:"token_url"`
	UserinfoURL          types.String `tfsdk:"userinfo_url"`
	SessionTTLSeconds    types.Int64  `tfsdk:"session_ttl_secs"`
	CreatedAt            types.String `tfsdk:"created_at"`
	UpdatedAt            types.String `tfsdk:"updated_at"`
}

func parseSsoProviderImportID(raw string, diags *diag.Diagnostics) (string, bool) {
	id := strings.TrimSpace(raw)
	if id == "" {
		diags.AddAttributeError(path.Root("id"), "Invalid Import ID", "An SSO provider UUID is required.")
		return "", false
	}
	return id, true
}
```

Also add shared helpers that:

- convert Terraform string sets to sorted `[]string`
- normalize absent API slices to empty Terraform sets
- preserve prior `client_secret` when `client_secret_configured` is true
- set `client_secret` to null when `client_secret_configured` is false
- add small test-local helpers in `resource_sso_provider_test.go` such as
  `ssoProviderSchema(t, res)` for schema extraction and any set-attribute assertions
  needed by the new tests
- build the full shared schema surface from the approved spec fields:
  `name`, `enabled`, `display_order`, `issuer_url`, `client_id`, `client_secret`,
  `scopes`, `pkce_required`, `subject_claim`, `email_claim`, `groups_claim`,
  `default_role`, `admin_subjects`, `admin_groups`, `admin_email_domains`,
  `readonly_subjects`, `readonly_groups`, `readonly_email_domains`,
  `allowed_email_domains`, `authorization_url`, `token_url`, `userinfo_url`,
  `session_ttl_secs`, `id`, `created_at`, and `updated_at`
- keep `name` required across all resources, collection attributes as unordered sets,
  and computed timestamps read-only

- [ ] **Step 5: Re-run the targeted shared-helper tests**

Run:

```bash
cd terraform-provider-neuwerk
go test ./internal/provider -run 'TestSsoProviderStateFromAPIPreservesSecretAndNormalizesSets|TestParseSsoProviderImportIDRejectsBlank' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit the shared-helper scaffolding**

```bash
git add terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go
git commit -m "feat(terraform): add shared SSO provider helpers"
```

### Task 2: Add SSO API Client Support and the Google Resource

**Files:**
- Modify: `terraform-provider-neuwerk/internal/provider/client.go`
- Modify: `terraform-provider-neuwerk/internal/provider/provider.go`
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_google.go`
- Modify: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go`

- [ ] **Step 1: Add failing Google CRUD, read-missing, and registration tests**

Extend `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go` with:

```go
func TestGoogleSsoProviderCreatePreservesSecretInState(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/settings/sso/providers" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if payload["kind"] != "google" {
			t.Fatalf("unexpected kind %#v", payload["kind"])
		}
		if payload["client_secret"] != "top-secret" {
			t.Fatalf("expected client_secret in create payload")
		}
		_, _ = w.Write([]byte(`{"id":"prov-1","name":"Corp Google","kind":"google","client_id":"client-1","client_secret_configured":true,"scopes":["openid","email"],"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	res := newSsoProviderGoogleResource()
	configurable := res.(resource.ResourceWithConfigure)
	configurable.Configure(context.Background(), resource.ConfigureRequest{
		ProviderData: newTestAPIClient(t, server),
	}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := ssoProviderSchema(t, res)
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := plan.Set(ctx, ssoProviderResourceModel{
		Name:         types.StringValue("Corp Google"),
		ClientID:     types.StringValue("client-1"),
		ClientSecret: types.StringValue("top-secret"),
	})
	if diags.HasError() {
		t.Fatalf("unexpected plan diagnostics: %#v", diags)
	}

	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	res.Create(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected create diagnostics: %#v", resp.Diagnostics)
	}

	var state ssoProviderResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected state diagnostics: %#v", resp.Diagnostics)
	}
	if state.ClientSecret.ValueString() != "top-secret" {
		t.Fatalf("expected create to preserve configured secret")
	}
}

func TestGoogleSsoProviderUpdateOmitsSecretWhenUnset(t *testing.T) {
	t.Parallel()

	var sawClientSecret bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			_, sawClientSecret = payload["client_secret"]
		}
		_, _ = w.Write([]byte(`{"id":"prov-1","name":"Corp Google","kind":"google","client_id":"client-1","client_secret_configured":true,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-02T00:00:00Z"}`))
	}))
	defer server.Close()

	res := newSsoProviderGoogleResource()
	configurable := res.(resource.ResourceWithConfigure)
	configurable.Configure(context.Background(), resource.ConfigureRequest{
		ProviderData: newTestAPIClient(t, server),
	}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := ssoProviderSchema(t, res)
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := plan.Set(ctx, ssoProviderResourceModel{
		ID:       types.StringValue("prov-1"),
		Name:     types.StringValue("Corp Google"),
		ClientID: types.StringValue("client-1"),
	})
	if diags.HasError() {
		t.Fatalf("unexpected plan diagnostics: %#v", diags)
	}

	req := resource.UpdateRequest{Plan: plan}
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	res.Update(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected update diagnostics: %#v", resp.Diagnostics)
	}
	if sawClientSecret {
		t.Fatalf("expected client_secret to be omitted from update payload")
	}
}

func TestGoogleSsoProviderReadRemovesStateWhenNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"sso provider not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	res := newSsoProviderGoogleResource()
	configurable := res.(resource.ResourceWithConfigure)
	configurable.Configure(context.Background(), resource.ConfigureRequest{
		ProviderData: newTestAPIClient(t, server),
	}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := ssoProviderSchema(t, res)
	state := tfsdk.State{Schema: schemaResp.Schema}
	diags := state.Set(ctx, ssoProviderResourceModel{
		ID:       types.StringValue("prov-404"),
		Name:     types.StringValue("Missing"),
		ClientID: types.StringValue("client-404"),
	})
	if diags.HasError() {
		t.Fatalf("unexpected state diagnostics: %#v", diags)
	}

	req := resource.ReadRequest{State: state}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	res.Read(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected read diagnostics: %#v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatalf("expected read to remove state on 404")
	}
}

func TestGoogleSsoProviderDeleteUsesProviderID(t *testing.T) {
	t.Parallel()

	var sawDeletePath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			sawDeletePath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()

	res := newSsoProviderGoogleResource()
	configurable := res.(resource.ResourceWithConfigure)
	configurable.Configure(context.Background(), resource.ConfigureRequest{
		ProviderData: newTestAPIClient(t, server),
	}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := ssoProviderSchema(t, res)
	state := tfsdk.State{Schema: schemaResp.Schema}
	diags := state.Set(ctx, ssoProviderResourceModel{
		ID:   types.StringValue("prov-1"),
		Name: types.StringValue("Corp Google"),
	})
	if diags.HasError() {
		t.Fatalf("unexpected state diagnostics: %#v", diags)
	}

	req := resource.DeleteRequest{State: state}
	resp := resource.DeleteResponse{}
	res.Delete(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected delete diagnostics: %#v", resp.Diagnostics)
	}
	if sawDeletePath != "/api/v1/settings/sso/providers/prov-1" {
		t.Fatalf("unexpected delete path %q", sawDeletePath)
	}
}

func TestProviderResourcesIncludeGoogleSsoProvider(t *testing.T) {
	t.Parallel()

	provider := New("test")()
	var found bool
	for _, factory := range provider.Resources(context.Background()) {
		res := factory()
		var resp resource.MetadataResponse
		res.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "neuwerk"}, &resp)
		if strings.HasSuffix(resp.TypeName, "_sso_provider_google") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected google sso provider registration")
	}
}
```

- [ ] **Step 2: Run the Google-focused tests and confirm they fail**

Run:

```bash
cd terraform-provider-neuwerk
go test ./internal/provider -run 'TestGoogleSsoProviderCreatePreservesSecretInState|TestGoogleSsoProviderUpdateOmitsSecretWhenUnset|TestGoogleSsoProviderReadRemovesStateWhenNotFound|TestGoogleSsoProviderDeleteUsesProviderID|TestProviderResourcesIncludeGoogleSsoProvider' -count=1
```

Expected: FAIL because the Google resource constructor, provider registration, and SSO client methods do not exist yet.

- [ ] **Step 3: Add SSO API request and response types to the shared client**

Update `terraform-provider-neuwerk/internal/provider/client.go` with types and methods like:

```go
type apiSsoProvider struct {
	ID                     string   `json:"id"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
	Name                   string   `json:"name"`
	Kind                   string   `json:"kind"`
	Enabled                bool     `json:"enabled"`
	DisplayOrder           int64    `json:"display_order"`
	IssuerURL              *string  `json:"issuer_url"`
	AuthorizationURL       *string  `json:"authorization_url"`
	TokenURL               *string  `json:"token_url"`
	UserinfoURL            *string  `json:"userinfo_url"`
	ClientID               string   `json:"client_id"`
	ClientSecretConfigured bool     `json:"client_secret_configured"`
	Scopes                 []string `json:"scopes"`
	PKCERequired           bool     `json:"pkce_required"`
	SubjectClaim           string   `json:"subject_claim"`
	EmailClaim             *string  `json:"email_claim"`
	GroupsClaim            *string  `json:"groups_claim"`
	DefaultRole            *string  `json:"default_role"`
	AdminSubjects          []string `json:"admin_subjects"`
	AdminGroups            []string `json:"admin_groups"`
	AdminEmailDomains      []string `json:"admin_email_domains"`
	ReadonlySubjects       []string `json:"readonly_subjects"`
	ReadonlyGroups         []string `json:"readonly_groups"`
	ReadonlyEmailDomains   []string `json:"readonly_email_domains"`
	AllowedEmailDomains    []string `json:"allowed_email_domains"`
	SessionTTLSeconds      int64    `json:"session_ttl_secs"`
}

type createSsoProviderRequest struct {
	Name                 string   `json:"name"`
	Kind                 string   `json:"kind"`
	Enabled              bool     `json:"enabled"`
	DisplayOrder         int64    `json:"display_order"`
	IssuerURL            *string  `json:"issuer_url,omitempty"`
	AuthorizationURL     *string  `json:"authorization_url,omitempty"`
	TokenURL             *string  `json:"token_url,omitempty"`
	UserinfoURL          *string  `json:"userinfo_url,omitempty"`
	ClientID             string   `json:"client_id"`
	ClientSecret         *string  `json:"client_secret,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	PKCERequired         bool     `json:"pkce_required"`
	SubjectClaim         string   `json:"subject_claim"`
	EmailClaim           *string  `json:"email_claim,omitempty"`
	GroupsClaim          *string  `json:"groups_claim,omitempty"`
	DefaultRole          *string  `json:"default_role,omitempty"`
	AdminSubjects        []string `json:"admin_subjects,omitempty"`
	AdminGroups          []string `json:"admin_groups,omitempty"`
	AdminEmailDomains    []string `json:"admin_email_domains,omitempty"`
	ReadonlySubjects     []string `json:"readonly_subjects,omitempty"`
	ReadonlyGroups       []string `json:"readonly_groups,omitempty"`
	ReadonlyEmailDomains []string `json:"readonly_email_domains,omitempty"`
	AllowedEmailDomains  []string `json:"allowed_email_domains,omitempty"`
	SessionTTLSeconds    int64    `json:"session_ttl_secs"`
}

func (c *apiClient) CreateSsoProvider(ctx context.Context, req createSsoProviderRequest) (*apiSsoProvider, error) {
	var out apiSsoProvider
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/settings/sso/providers", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) ListSsoProviders(ctx context.Context) ([]apiSsoProvider, error) { /* ... */ }
```

Also add `GetSsoProvider`, `UpdateSsoProvider`, and `DeleteSsoProvider`.

- [ ] **Step 4: Implement the Google resource wrapper and register it**

Create `terraform-provider-neuwerk/internal/provider/resource_sso_provider_google.go` with a thin wrapper like:

```go
func newSsoProviderGoogleResource() resource.Resource {
	return newSsoProviderResource(ssoProviderKindConfig{
		resourceSuffix: "_sso_provider_google",
		apiKind:        "google",
	})
}
```

Update `terraform-provider-neuwerk/internal/provider/provider.go` to register `newSsoProviderGoogleResource` in `Resources`.

Wire the shared implementation so `Create`, `Read`, `Update`, `Delete`, and `ImportState` all use the client methods from `client.go`.

- [ ] **Step 5: Re-run the Google-focused tests**

Run:

```bash
cd terraform-provider-neuwerk
go test ./internal/provider -run 'TestGoogleSsoProviderCreatePreservesSecretInState|TestGoogleSsoProviderUpdateOmitsSecretWhenUnset|TestGoogleSsoProviderReadRemovesStateWhenNotFound|TestGoogleSsoProviderDeleteUsesProviderID|TestProviderResourcesIncludeGoogleSsoProvider' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit the Google resource slice**

```bash
git add terraform-provider-neuwerk/internal/provider/client.go terraform-provider-neuwerk/internal/provider/provider.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_google.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go
git commit -m "feat(terraform): add google SSO provider resource"
```

### Task 3: Add the GitHub Resource and Shared Refresh Convergence Coverage

**Files:**
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_github.go`
- Modify: `terraform-provider-neuwerk/internal/provider/provider.go`
- Modify: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go`

- [ ] **Step 1: Add failing GitHub schema and refresh-convergence tests**

Extend `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go` with:

```go
func TestGithubSsoProviderSchemaMarksClientSecretSensitive(t *testing.T) {
	t.Parallel()

	res := newSsoProviderGithubResource()
	var schemaResp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	attr := schemaResp.Schema.Attributes["client_secret"].(resourceschema.StringAttribute)
	if !attr.Sensitive || !attr.Optional || attr.Computed {
		t.Fatalf("unexpected client_secret schema: %#v", attr)
	}
}

func TestSsoProviderStateFromAPIAcceptsDefaultedEndpoints(t *testing.T) {
	t.Parallel()

	prior := ssoProviderResourceModel{}
	record := &apiSsoProvider{
		ID:                     "prov-2",
		Name:                   "Corp GitHub",
		Kind:                   "github",
		ClientID:               "client-2",
		ClientSecretConfigured: true,
		AuthorizationURL:       stringPtr("https://github.com/login/oauth/authorize"),
		TokenURL:               stringPtr("https://github.com/login/oauth/access_token"),
		UserinfoURL:            stringPtr("https://api.github.com/user"),
	}

	state := ssoProviderStateFromAPI(prior, record)
	if state.AuthorizationURL.IsNull() {
		t.Fatalf("expected effective endpoint in state")
	}
}
```

- [ ] **Step 2: Run the GitHub-focused tests and confirm they fail**

Run:

```bash
cd terraform-provider-neuwerk
go test ./internal/provider -run 'TestGithubSsoProviderSchemaMarksClientSecretSensitive|TestSsoProviderStateFromAPIAcceptsDefaultedEndpoints' -count=1
```

Expected: FAIL because the GitHub resource wrapper does not exist yet and the shared model does not fully map endpoint fields.

- [ ] **Step 3: Extend the shared model to cover endpoint overrides and common fields**

Update `terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go` so the shared model and request builders include:

```go
AuthorizationURL types.String `tfsdk:"authorization_url"`
TokenURL         types.String `tfsdk:"token_url"`
UserinfoURL      types.String `tfsdk:"userinfo_url"`
IssuerURL        types.String `tfsdk:"issuer_url"`
PKCERequired     types.Bool   `tfsdk:"pkce_required"`
DefaultRole      types.String `tfsdk:"default_role"`
```

Also add mapping helpers that:

- carry API-returned effective endpoint defaults into Terraform state
- normalize missing collections to empty sets
- keep `name` required across all three resources

- [ ] **Step 4: Implement the GitHub wrapper and register it**

Create `terraform-provider-neuwerk/internal/provider/resource_sso_provider_github.go` with:

```go
func newSsoProviderGithubResource() resource.Resource {
	return newSsoProviderResource(ssoProviderKindConfig{
		resourceSuffix: "_sso_provider_github",
		apiKind:        "github",
	})
}
```

Add the GitHub factory to `terraform-provider-neuwerk/internal/provider/provider.go`.

- [ ] **Step 5: Re-run the GitHub-focused tests**

Run:

```bash
cd terraform-provider-neuwerk
go test ./internal/provider -run 'TestGithubSsoProviderSchemaMarksClientSecretSensitive|TestSsoProviderStateFromAPIAcceptsDefaultedEndpoints' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit the GitHub resource slice**

```bash
git add terraform-provider-neuwerk/internal/provider/provider.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_github.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go
git commit -m "feat(terraform): add github SSO provider resource"
```

### Task 4: Add the Generic OIDC Resource, Import Semantics, and Kind Safety

**Files:**
- Create: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_generic_oidc.go`
- Modify: `terraform-provider-neuwerk/internal/provider/provider.go`
- Modify: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go`
- Modify: `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go`

- [ ] **Step 1: Add failing Generic OIDC validation and kind-mismatch tests**

Extend `terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go` with:

```go
func TestGenericOidcSchemaRequiresExplicitEndpoints(t *testing.T) {
	t.Parallel()

	res := newSsoProviderGenericOIDCResource()
	var schemaResp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

	authAttr := schemaResp.Schema.Attributes["authorization_url"].(resourceschema.StringAttribute)
	if !authAttr.Required {
		t.Fatalf("expected authorization_url to be required")
	}
}

func TestSsoProviderReadFailsOnKindMismatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"prov-3","name":"Wrong Kind","kind":"github","client_id":"client-3","client_secret_configured":true,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	res := newSsoProviderGenericOIDCResource()
	configurable := res.(resource.ResourceWithConfigure)
	configurable.Configure(context.Background(), resource.ConfigureRequest{
		ProviderData: newTestAPIClient(t, server),
	}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := ssoProviderSchema(t, res)
	state := tfsdk.State{Schema: schemaResp.Schema}
	diags := state.Set(ctx, ssoProviderResourceModel{
		ID:   types.StringValue("prov-3"),
		Name: types.StringValue("Wrong Kind"),
	})
	if diags.HasError() {
		t.Fatalf("unexpected state diagnostics: %#v", diags)
	}

	req := resource.ReadRequest{State: state}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	res.Read(ctx, req, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected kind mismatch diagnostics")
	}
}

func TestSsoProviderImportStateStartsWithoutSecret(t *testing.T) {
	t.Parallel()

	res := newSsoProviderGithubResource()
	importable := res.(resource.ResourceWithImportState)
	ctx := context.Background()
	schemaResp := ssoProviderSchema(t, res)

	resp := resource.ImportStateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	resp.State.Raw = tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)
	importable.ImportState(ctx, resource.ImportStateRequest{ID: "prov-7"}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}

	var state ssoProviderResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if !state.ClientSecret.IsNull() {
		t.Fatalf("expected imported client_secret to remain null")
	}
}
```

- [ ] **Step 2: Run the Generic OIDC-focused tests and confirm they fail**

Run:

```bash
cd terraform-provider-neuwerk
go test ./internal/provider -run 'TestGenericOidcSchemaRequiresExplicitEndpoints|TestSsoProviderReadFailsOnKindMismatch|TestSsoProviderImportStateStartsWithoutSecret' -count=1
```

Expected: FAIL because the Generic OIDC resource wrapper does not exist yet and the shared read path does not enforce kind matching.

- [ ] **Step 3: Implement Generic OIDC-specific schema overlays and kind checks**

Update `terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go` so the shared schema builder can switch endpoint attributes between optional and required:

```go
func ssoEndpointAttribute(required bool) resourceschema.StringAttribute {
	return resourceschema.StringAttribute{
		Required: required,
		Optional: !required,
	}
}
```

In the shared `Read` path, add a guard like:

```go
if record.Kind != r.kind.apiKind {
	resp.Diagnostics.AddError(
		"SSO Provider Kind Mismatch",
		fmt.Sprintf("resource expects kind %q but API returned %q", r.kind.apiKind, record.Kind),
	)
	return
}
```

- [ ] **Step 4: Implement the Generic OIDC wrapper and register it**

Create `terraform-provider-neuwerk/internal/provider/resource_sso_provider_generic_oidc.go` with:

```go
func newSsoProviderGenericOIDCResource() resource.Resource {
	return newSsoProviderResource(ssoProviderKindConfig{
		resourceSuffix:           "_sso_provider_generic_oidc",
		apiKind:                  "generic-oidc",
		requireExplicitEndpoints: true,
	})
}
```

Add the Generic OIDC factory to `terraform-provider-neuwerk/internal/provider/provider.go`.

- [ ] **Step 5: Re-run the Generic OIDC-focused tests**

Run:

```bash
cd terraform-provider-neuwerk
go test ./internal/provider -run 'TestGenericOidcSchemaRequiresExplicitEndpoints|TestSsoProviderReadFailsOnKindMismatch|TestSsoProviderImportStateStartsWithoutSecret' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit the Generic OIDC resource slice**

```bash
git add terraform-provider-neuwerk/internal/provider/provider.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_shared.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_generic_oidc.go terraform-provider-neuwerk/internal/provider/resource_sso_provider_test.go
git commit -m "feat(terraform): add generic OIDC SSO provider resource"
```

### Task 5: Document the Resources and Run Full Verification

**Files:**
- Modify: `terraform-provider-neuwerk/README.md`

- [ ] **Step 1: Verify the README does not yet mention SSO provider resources**

Run:

```bash
cd terraform-provider-neuwerk
rg -n "sso_provider|generic_oidc|GitHub SSO|Google SSO|client_secret" README.md
```

Expected: no SSO resource matches yet.

- [ ] **Step 2: Add concise README examples and lifecycle notes**

Update `terraform-provider-neuwerk/README.md` so the implemented resources list includes:

```markdown
- `neuwerk_sso_provider_google`
- `neuwerk_sso_provider_github`
- `neuwerk_sso_provider_generic_oidc`
```

Add one short example for each resource kind:

```hcl
resource "neuwerk_sso_provider_google" "corp" {
  name          = "Corp Google"
  client_id     = var.google_client_id
  client_secret = var.google_client_secret
  scopes        = ["openid", "email", "profile"]
}

resource "neuwerk_sso_provider_github" "corp" {
  name          = "Corp GitHub"
  client_id     = var.github_client_id
  client_secret = var.github_client_secret
}

resource "neuwerk_sso_provider_generic_oidc" "corp" {
  name              = "Corp OIDC"
  client_id         = var.oidc_client_id
  client_secret     = var.oidc_client_secret
  authorization_url = "https://idp.example.com/oauth2/authorize"
  token_url         = "https://idp.example.com/oauth2/token"
  userinfo_url      = "https://idp.example.com/oauth2/userinfo"
}
```

Also add two short notes:

```markdown
- All SSO provider resources import by provider UUID.
- `client_secret` is required on create, stored as a sensitive value in Terraform state, and cannot be recovered from the API during import.
```

- [ ] **Step 3: Verify the README now contains all required SSO docs**

Run:

```bash
cd terraform-provider-neuwerk
rg -n "neuwerk_sso_provider_google|neuwerk_sso_provider_github|neuwerk_sso_provider_generic_oidc|import by provider UUID|required on create" README.md
```

Expected: matching lines for all three resources and both lifecycle notes.

- [ ] **Step 4: Run the full Terraform provider verification**

Run:

```bash
cd terraform-provider-neuwerk
go test ./... -count=1
git diff --check
```

Expected:

- `go test` passes
- `git diff --check` prints no output

- [ ] **Step 5: Commit the docs and final verification state**

```bash
git add terraform-provider-neuwerk/README.md
git commit -m "docs(terraform): document SSO provider resources"
```

## Execution Notes

- Keep `client_secret` schema optional+sensitive and enforce create-time presence in resource code, not schema metadata.
- Normalize set-like attributes to empty sets rather than null after reads so omitted API arrays do not cause perpetual diffs.
- Treat `404` on `Read` as resource removal, consistent with existing provider resources.
- Keep per-kind files thin. Shared validation, request building, and state mapping belong in `resource_sso_provider_shared.go`.
- Do not add data sources, secret-manager hooks, or `/test` action support in this plan.
