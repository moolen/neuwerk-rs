package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestParseServiceAccountTokenImportID(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	serviceAccountID, tokenID, ok := parseServiceAccountTokenImportID(" acc-123/tok-456 ", &diags)
	if !ok {
		t.Fatalf("expected import id to parse")
	}
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", diags)
	}
	if serviceAccountID != "acc-123" {
		t.Fatalf("unexpected service account id %q", serviceAccountID)
	}
	if tokenID != "tok-456" {
		t.Fatalf("unexpected token id %q", tokenID)
	}
}

func TestParseServiceAccountTokenImportIDRejectsInvalidShape(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"   ",
		"acc-123",
		"acc-123/",
		"/tok-456",
		"acc-123/tok-456/extra",
	}

	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics
			if _, _, ok := parseServiceAccountTokenImportID(raw, &diags); ok {
				t.Fatalf("expected import id %q to be rejected", raw)
			}
			if !diags.HasError() {
				t.Fatalf("expected diagnostics for %q", raw)
			}
		})
	}
}

func TestServiceAccountTokenStateFromAPIKeepsPriorSecret(t *testing.T) {
	t.Parallel()

	prior := serviceAccountTokenResourceModel{
		ServiceAccountID: types.StringValue("acc-1"),
		Name:             types.StringValue("deploy token"),
		Role:             types.StringValue("readonly"),
		Token:            types.StringValue("signed-token"),
	}
	record := &apiServiceAccountTokenMeta{
		ID:               "tok-1",
		ServiceAccountID: "acc-1",
		Name:             stringPtr("deploy token"),
		CreatedAt:        "2024-01-01T00:00:00Z",
		CreatedBy:        "admin",
		ExpiresAt:        stringPtr("2024-01-02T00:00:00Z"),
		RevokedAt:        nil,
		LastUsedAt:       stringPtr("2024-01-01T12:00:00Z"),
		Kid:              "kid-1",
		Role:             "readonly",
		Status:           "active",
	}

	state := serviceAccountTokenStateFromAPI(prior, record)

	if state.ID.ValueString() != "tok-1" {
		t.Fatalf("unexpected id %q", state.ID.ValueString())
	}
	if state.ServiceAccountID.ValueString() != "acc-1" {
		t.Fatalf("unexpected service account id %q", state.ServiceAccountID.ValueString())
	}
	if state.Name.ValueString() != "deploy token" {
		t.Fatalf("unexpected name %q", state.Name.ValueString())
	}
	if state.Token.ValueString() != "signed-token" {
		t.Fatalf("expected prior token to be preserved, got %q", state.Token.ValueString())
	}
	if state.CreatedAt.ValueString() != "2024-01-01T00:00:00Z" {
		t.Fatalf("unexpected created_at %q", state.CreatedAt.ValueString())
	}
	if state.CreatedBy.ValueString() != "admin" {
		t.Fatalf("unexpected created_by %q", state.CreatedBy.ValueString())
	}
	if state.ExpiresAt.ValueString() != "2024-01-02T00:00:00Z" {
		t.Fatalf("unexpected expires_at %q", state.ExpiresAt.ValueString())
	}
	if !state.RevokedAt.IsNull() {
		t.Fatalf("expected revoked_at to be null")
	}
	if state.LastUsedAt.ValueString() != "2024-01-01T12:00:00Z" {
		t.Fatalf("unexpected last_used_at %q", state.LastUsedAt.ValueString())
	}
	if state.Kid.ValueString() != "kid-1" {
		t.Fatalf("unexpected kid %q", state.Kid.ValueString())
	}
	if state.Role.ValueString() != "readonly" {
		t.Fatalf("unexpected role %q", state.Role.ValueString())
	}
	if state.Status.ValueString() != "active" {
		t.Fatalf("unexpected status %q", state.Status.ValueString())
	}
}

func TestServiceAccountTokenStateFromAPIPreservesManagedInputs(t *testing.T) {
	t.Parallel()

	prior := serviceAccountTokenResourceModel{
		ServiceAccountID: types.StringValue("acc-keep"),
		Name:             types.StringNull(),
		TTL:              types.StringValue("24h"),
		Eternal:          types.BoolValue(false),
		Role:             types.StringNull(),
		Token:            types.StringValue("signed-token"),
	}
	record := &apiServiceAccountTokenMeta{
		ID:               "tok-1",
		ServiceAccountID: "acc-from-api",
		Name:             stringPtr("effective token name"),
		CreatedAt:        "2024-01-01T00:00:00Z",
		CreatedBy:        "admin",
		ExpiresAt:        stringPtr("2024-01-02T00:00:00Z"),
		RevokedAt:        nil,
		LastUsedAt:       stringPtr("2024-01-01T12:00:00Z"),
		Kid:              "kid-1",
		Role:             "readonly",
		Status:           "active",
	}

	state := serviceAccountTokenStateFromAPI(prior, record)

	if state.ServiceAccountID.ValueString() != "acc-keep" {
		t.Fatalf("service_account_id should preserve prior value, got %q", state.ServiceAccountID.ValueString())
	}
	if !state.Name.IsNull() {
		t.Fatalf("name should preserve prior null value, got %q", state.Name.ValueString())
	}
	if state.TTL.ValueString() != "24h" {
		t.Fatalf("ttl should preserve prior value, got %q", state.TTL.ValueString())
	}
	if state.Eternal.ValueBool() {
		t.Fatalf("eternal should preserve prior false value")
	}
	if !state.Role.IsNull() {
		t.Fatalf("role should preserve prior null value, got %q", state.Role.ValueString())
	}
	if state.Token.ValueString() != "signed-token" {
		t.Fatalf("token should preserve prior value, got %q", state.Token.ValueString())
	}

	if state.ID.ValueString() != "tok-1" {
		t.Fatalf("unexpected id %q", state.ID.ValueString())
	}
	if state.CreatedAt.ValueString() != "2024-01-01T00:00:00Z" {
		t.Fatalf("unexpected created_at %q", state.CreatedAt.ValueString())
	}
	if state.CreatedBy.ValueString() != "admin" {
		t.Fatalf("unexpected created_by %q", state.CreatedBy.ValueString())
	}
	if state.ExpiresAt.ValueString() != "2024-01-02T00:00:00Z" {
		t.Fatalf("unexpected expires_at %q", state.ExpiresAt.ValueString())
	}
	if !state.RevokedAt.IsNull() {
		t.Fatalf("expected revoked_at to be null")
	}
	if state.LastUsedAt.ValueString() != "2024-01-01T12:00:00Z" {
		t.Fatalf("unexpected last_used_at %q", state.LastUsedAt.ValueString())
	}
	if state.Kid.ValueString() != "kid-1" {
		t.Fatalf("unexpected kid %q", state.Kid.ValueString())
	}
	if state.Status.ValueString() != "active" {
		t.Fatalf("unexpected status %q", state.Status.ValueString())
	}
}

func TestServiceAccountTokenImportStateStartsWithoutRawToken(t *testing.T) {
	t.Parallel()

	res := newServiceAccountTokenResource()
	importable, ok := res.(resource.ResourceWithImportState)
	if !ok {
		t.Fatalf("resource does not implement import state")
	}
	ctx := context.Background()
	schemaResp := serviceAccountTokenSchema(t)

	resp := resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema},
	}
	resp.State.Raw = tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)
	req := resource.ImportStateRequest{ID: "acc-123/tok-456"}
	importable.ImportState(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}

	var state serviceAccountTokenResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics after state read: %#v", resp.Diagnostics)
	}
	if state.ServiceAccountID.ValueString() != "acc-123" {
		t.Fatalf("unexpected service account id %q", state.ServiceAccountID.ValueString())
	}
	if state.ID.ValueString() != "tok-456" {
		t.Fatalf("unexpected token id %q", state.ID.ValueString())
	}
	if !state.Token.IsNull() {
		t.Fatalf("expected imported token to be null")
	}
}

func TestServiceAccountTokenCreateCanonicalizesServiceAccountIDInState(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts/acc-123/tokens" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(payload) != 0 {
			t.Fatalf("expected empty create payload, got %#v", payload)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"token":"signed-token",
			"token_meta":{
				"id":"tok-1",
				"service_account_id":"acc-123",
				"name":null,
				"created_at":"2024-01-01T00:00:00Z",
				"created_by":"admin",
				"expires_at":null,
				"revoked_at":null,
				"last_used_at":null,
				"kid":"kid-1",
				"role":"readonly",
				"status":"active"
			}
		}`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	res := newServiceAccountTokenResource()
	configurable, ok := res.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("resource does not implement configure")
	}
	configurable.Configure(context.Background(), resource.ConfigureRequest{ProviderData: client}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := serviceAccountTokenSchema(t)
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := plan.Set(ctx, serviceAccountTokenResourceModel{
		ServiceAccountID: types.StringValue("  acc-123  "),
	})
	if diags.HasError() {
		t.Fatalf("unexpected plan diagnostics: %#v", diags)
	}

	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}

	res.Create(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}

	var state serviceAccountTokenResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics reading state: %#v", resp.Diagnostics)
	}
	if state.ServiceAccountID.ValueString() != "acc-123" {
		t.Fatalf("expected canonical service_account_id, got %q", state.ServiceAccountID.ValueString())
	}
	if state.Token.ValueString() != "signed-token" {
		t.Fatalf("unexpected token %q", state.Token.ValueString())
	}
}

func TestServiceAccountTokenReadHydratesImportedMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts/acc-123/tokens" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{
				"id":"tok-456",
				"service_account_id":"acc-123",
				"name":"imported token",
				"created_at":"2024-01-01T00:00:00Z",
				"created_by":"admin",
				"expires_at":"2024-01-02T00:00:00Z",
				"revoked_at":null,
				"last_used_at":"2024-01-01T12:00:00Z",
				"kid":"kid-1",
				"role":"readonly",
				"status":"active"
			}
		]`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	res := newServiceAccountTokenResource()
	configurable, ok := res.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("resource does not implement configure")
	}
	configurable.Configure(context.Background(), resource.ConfigureRequest{ProviderData: client}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := serviceAccountTokenSchema(t)
	state := tfsdk.State{Schema: schemaResp.Schema}
	diags := state.Set(ctx, serviceAccountTokenResourceModel{
		ID:               types.StringValue("tok-456"),
		ServiceAccountID: types.StringValue("acc-123"),
	})
	if diags.HasError() {
		t.Fatalf("unexpected state diagnostics: %#v", diags)
	}

	req := resource.ReadRequest{State: state}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}

	res.Read(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}

	var next serviceAccountTokenResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &next)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics reading state: %#v", resp.Diagnostics)
	}
	if next.Name.ValueString() != "imported token" {
		t.Fatalf("expected imported name to hydrate from API, got %q", next.Name.ValueString())
	}
	if next.Role.ValueString() != "readonly" {
		t.Fatalf("expected imported role to hydrate from API, got %q", next.Role.ValueString())
	}
	if next.CreatedAt.ValueString() != "2024-01-01T00:00:00Z" {
		t.Fatalf("unexpected created_at %q", next.CreatedAt.ValueString())
	}
	if next.CreatedBy.ValueString() != "admin" {
		t.Fatalf("unexpected created_by %q", next.CreatedBy.ValueString())
	}
	if next.ExpiresAt.ValueString() != "2024-01-02T00:00:00Z" {
		t.Fatalf("unexpected expires_at %q", next.ExpiresAt.ValueString())
	}
	if next.LastUsedAt.ValueString() != "2024-01-01T12:00:00Z" {
		t.Fatalf("unexpected last_used_at %q", next.LastUsedAt.ValueString())
	}
	if next.Token.IsNull() == false {
		t.Fatalf("expected imported token secret to remain unavailable")
	}
}

func TestServiceAccountTokenReadRemovesRevokedToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts/acc-123/tokens" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{
				"id":"tok-456",
				"service_account_id":"acc-123",
				"name":"revoked token",
				"created_at":"2024-01-01T00:00:00Z",
				"created_by":"admin",
				"expires_at":null,
				"revoked_at":"2024-01-02T00:00:00Z",
				"last_used_at":null,
				"kid":"kid-1",
				"role":"readonly",
				"status":"revoked"
			}
		]`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	res := newServiceAccountTokenResource()
	configurable, ok := res.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("resource does not implement configure")
	}
	configurable.Configure(context.Background(), resource.ConfigureRequest{ProviderData: client}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := serviceAccountTokenSchema(t)
	state := tfsdk.State{Schema: schemaResp.Schema}
	diags := state.Set(ctx, serviceAccountTokenResourceModel{
		ID:               types.StringValue("tok-456"),
		ServiceAccountID: types.StringValue("acc-123"),
		Name:             types.StringValue("revoked token"),
		Role:             types.StringValue("readonly"),
	})
	if diags.HasError() {
		t.Fatalf("unexpected state diagnostics: %#v", diags)
	}

	req := resource.ReadRequest{State: state}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}

	res.Read(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatalf("expected revoked token to be removed from state")
	}
}

func TestServiceAccountTokenSchemaMarksReplaceOnCredentialInputs(t *testing.T) {
	t.Parallel()

	schemaResp := serviceAccountTokenSchema(t)

	assertStringAttribute(t, schemaResp.Schema.Attributes, "service_account_id", true, false, false)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "name", false, true, false)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "ttl", false, true, false)
	assertBoolAttribute(t, schemaResp.Schema.Attributes, "eternal", false, true, false)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "role", false, true, false)
	assertSensitiveComputedStringAttribute(t, schemaResp.Schema.Attributes, "token")

	assertStringReplaceModifier(t, schemaResp.Schema.Attributes, "service_account_id")
	assertStringReplaceModifier(t, schemaResp.Schema.Attributes, "name")
	assertStringReplaceModifier(t, schemaResp.Schema.Attributes, "ttl")
	assertBoolReplaceModifier(t, schemaResp.Schema.Attributes, "eternal")
	assertStringReplaceModifier(t, schemaResp.Schema.Attributes, "role")
}

func TestFindServiceAccountTokenReturnsMatchByID(t *testing.T) {
	t.Parallel()

	tokens := []apiServiceAccountTokenMeta{
		{ID: "tok-1", ServiceAccountID: "acc-1"},
		{ID: "tok-2", ServiceAccountID: "acc-1", Kid: "kid-2"},
	}

	record := findServiceAccountToken(tokens, "tok-2")
	if record == nil {
		t.Fatalf("expected token match")
	}
	if record.ID != "tok-2" {
		t.Fatalf("unexpected token id %q", record.ID)
	}
	if record.Kid != "kid-2" {
		t.Fatalf("unexpected kid %q", record.Kid)
	}
}

func TestServiceAccountTokenUpdateAlwaysErrors(t *testing.T) {
	t.Parallel()

	res := newServiceAccountTokenResource().(resource.Resource)
	ctx := context.Background()
	schemaResp := serviceAccountTokenSchema(t)

	resp := resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema},
	}
	resp.State.Raw = tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)

	res.Update(ctx, resource.UpdateRequest{}, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected update diagnostics error")
	}
	if got := resp.Diagnostics.Errors()[0].Detail(); got != "Service account tokens are immutable; replace the resource to mint a new token." {
		t.Fatalf("unexpected error detail %q", got)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatalf("expected update path not to mutate state")
	}
}

func TestProviderResourcesIncludeServiceAccountToken(t *testing.T) {
	t.Parallel()

	provider := New("test")()
	resources := provider.Resources(context.Background())
	if len(resources) == 0 {
		t.Fatalf("expected resource registrations")
	}

	var found bool
	for _, factory := range resources {
		res := factory()
		var resp resource.MetadataResponse
		res.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "neuwerk"}, &resp)
		if strings.HasSuffix(resp.TypeName, "_service_account_token") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected service account token resource registration")
	}
}

func serviceAccountTokenSchema(t *testing.T) resource.SchemaResponse {
	t.Helper()

	res := newServiceAccountTokenResource()
	var schemaResp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp
}

func assertBoolAttribute(t *testing.T, attrs map[string]resourceschema.Attribute, name string, required bool, optional bool, computed bool) {
	t.Helper()

	attr, ok := attrs[name]
	if !ok {
		t.Fatalf("missing attribute %q", name)
	}
	boolAttr, ok := attr.(resourceschema.BoolAttribute)
	if !ok {
		t.Fatalf("attribute %q is not a bool attribute", name)
	}
	if boolAttr.Required != required {
		t.Fatalf("attribute %q required=%v expected %v", name, boolAttr.Required, required)
	}
	if boolAttr.Optional != optional {
		t.Fatalf("attribute %q optional=%v expected %v", name, boolAttr.Optional, optional)
	}
	if boolAttr.Computed != computed {
		t.Fatalf("attribute %q computed=%v expected %v", name, boolAttr.Computed, computed)
	}
}

func assertSensitiveComputedStringAttribute(t *testing.T, attrs map[string]resourceschema.Attribute, name string) {
	t.Helper()

	attr, ok := attrs[name]
	if !ok {
		t.Fatalf("missing attribute %q", name)
	}
	stringAttr, ok := attr.(resourceschema.StringAttribute)
	if !ok {
		t.Fatalf("attribute %q is not a string attribute", name)
	}
	if !stringAttr.Computed {
		t.Fatalf("attribute %q should be computed", name)
	}
	if !stringAttr.Sensitive {
		t.Fatalf("attribute %q should be sensitive", name)
	}
}

func assertStringReplaceModifier(t *testing.T, attrs map[string]resourceschema.Attribute, name string) {
	t.Helper()

	attr, ok := attrs[name]
	if !ok {
		t.Fatalf("missing attribute %q", name)
	}
	stringAttr, ok := attr.(resourceschema.StringAttribute)
	if !ok {
		t.Fatalf("attribute %q is not a string attribute", name)
	}
	if len(stringAttr.PlanModifiers) == 0 {
		t.Fatalf("attribute %q missing plan modifiers", name)
	}
	if !strings.Contains(stringAttr.PlanModifiers[0].Description(context.Background()), "destroy and recreate the resource") {
		t.Fatalf("attribute %q missing requires-replace plan modifier", name)
	}
}

func assertBoolReplaceModifier(t *testing.T, attrs map[string]resourceschema.Attribute, name string) {
	t.Helper()

	attr, ok := attrs[name]
	if !ok {
		t.Fatalf("missing attribute %q", name)
	}
	boolAttr, ok := attr.(resourceschema.BoolAttribute)
	if !ok {
		t.Fatalf("attribute %q is not a bool attribute", name)
	}
	if len(boolAttr.PlanModifiers) == 0 {
		t.Fatalf("attribute %q missing plan modifiers", name)
	}
	if !strings.Contains(boolAttr.PlanModifiers[0].Description(context.Background()), "destroy and recreate the resource") {
		t.Fatalf("attribute %q missing requires-replace plan modifier", name)
	}
}
