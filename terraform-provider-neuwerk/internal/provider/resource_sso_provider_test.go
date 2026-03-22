package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestSsoProviderStateFromAPIPreservesSecretAndNormalizesSets(t *testing.T) {
	t.Parallel()

	prior := ssoProviderResourceModel{
		ClientSecret: types.StringValue("super-secret"),
		Scopes: setStringValues(
			types.StringValue("email"),
			types.StringValue("openid"),
		),
	}
	record := &apiSsoProvider{
		ID:                     "sso-1",
		Name:                   "corp-oidc",
		Enabled:                true,
		DisplayOrder:           7,
		IssuerURL:              "https://issuer.example.com",
		ClientID:               "client-id",
		ClientSecretConfigured: true,
		AdminGroups:            []string{"ops", "admins"},
	}

	state := ssoProviderStateFromAPI(prior, record)

	if state.ClientSecret.ValueString() != "super-secret" {
		t.Fatalf("expected prior client_secret to be preserved, got %q", state.ClientSecret.ValueString())
	}
	assertStringSetElements(t, state.Scopes, []string{})
	assertStringSetElements(t, state.AdminGroups, []string{"admins", "ops"})

	record.ClientSecretConfigured = false
	state = ssoProviderStateFromAPI(prior, record)
	if !state.ClientSecret.IsNull() {
		t.Fatalf("expected client_secret to be null when client_secret_configured=false")
	}
}

func TestParseSsoProviderImportIDRejectsBlank(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	if _, ok := parseSsoProviderImportID("   ", &diags); ok {
		t.Fatalf("expected empty import id to be rejected")
	}
	if !diags.HasError() {
		t.Fatalf("expected diagnostics error")
	}
}

func TestSsoProviderStateFromAPIPreservesUnknownSecretWhenConfigured(t *testing.T) {
	t.Parallel()

	prior := ssoProviderResourceModel{
		ClientSecret: types.StringUnknown(),
	}
	record := &apiSsoProvider{
		ID:                     "sso-1",
		Name:                   "corp-oidc",
		ClientSecretConfigured: true,
	}

	state := ssoProviderStateFromAPI(prior, record)
	if !state.ClientSecret.IsUnknown() {
		t.Fatalf("expected unknown client_secret to be preserved when configured")
	}
}

func TestSsoProviderSetToSortedStringsSortsAndDedupes(t *testing.T) {
	t.Parallel()

	input := setStringValues(
		types.StringValue("z"),
		types.StringValue("a"),
		types.StringValue("m"),
	)

	var diags diag.Diagnostics
	got := ssoProviderSetToSortedStrings(input, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", diags)
	}

	want := []string{"a", "m", "z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected result: got %#v want %#v", got, want)
	}
}

func TestSsoProviderSetToSortedStringsNullReturnsNil(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := ssoProviderSetToSortedStrings(types.SetNull(types.StringType), &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", diags)
	}
	if got != nil {
		t.Fatalf("expected nil for null set, got %#v", got)
	}
}

func TestSsoProviderSetToSortedStringsUnknownReturnsNil(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	got := ssoProviderSetToSortedStrings(types.SetUnknown(types.StringType), &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", diags)
	}
	if got != nil {
		t.Fatalf("expected nil for unknown set, got %#v", got)
	}
}

func TestSsoProviderSetToSortedStringsKnownEmptyReturnsEmptySlice(t *testing.T) {
	t.Parallel()

	empty, diags := types.SetValue(types.StringType, []attr.Value{})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics creating empty set: %#v", diags)
	}

	var runDiags diag.Diagnostics
	got := ssoProviderSetToSortedStrings(empty, &runDiags)
	if runDiags.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", runDiags)
	}
	if got == nil {
		t.Fatalf("expected empty slice for known empty set, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %#v", got)
	}
}

func TestGoogleSsoProviderCreatePreservesSecretInState(t *testing.T) {
	t.Parallel()

	var sawCreate bool
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
			t.Fatalf("unexpected kind payload %#v", payload["kind"])
		}
		if payload["client_secret"] != "super-secret" {
			t.Fatalf("unexpected client_secret payload %#v", payload["client_secret"])
		}
		sawCreate = true

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"26fd7f8d-4f9f-4e0f-a252-a86bb0f018f6",
			"name":"Google Workspace",
			"kind":"google",
			"enabled":true,
			"display_order":0,
			"issuer_url":"https://accounts.google.com",
			"client_id":"google-client-id",
			"client_secret_configured":true,
			"scopes":["openid","email","profile"],
			"pkce_required":true,
			"subject_claim":"sub",
			"admin_subjects":[],
			"admin_groups":[],
			"admin_email_domains":[],
			"readonly_subjects":[],
			"readonly_groups":[],
			"readonly_email_domains":[],
			"allowed_email_domains":[],
			"session_ttl_secs":3600,
			"created_at":"2026-03-22T00:00:00Z",
			"updated_at":"2026-03-22T00:00:00Z"
		}`))
	}))
	defer server.Close()

	res := newGoogleSsoProviderResource()
	configurable, ok := res.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("resource does not implement configure")
	}
	configurable.Configure(context.Background(), resource.ConfigureRequest{ProviderData: newTestAPIClient(t, server)}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := googleSsoProviderSchema(t)
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	planValue := emptyGoogleSsoProviderModel()
	planValue.Name = types.StringValue("Google Workspace")
	planValue.ClientID = types.StringValue("google-client-id")
	planValue.ClientSecret = types.StringValue("super-secret")
	diags := plan.Set(ctx, planValue)
	if diags.HasError() {
		t.Fatalf("unexpected plan diagnostics: %#v", diags)
	}

	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	res.Create(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}
	if !sawCreate {
		t.Fatalf("expected create request to be sent")
	}

	var state ssoProviderResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected state diagnostics: %#v", resp.Diagnostics)
	}
	if state.ClientSecret.ValueString() != "super-secret" {
		t.Fatalf("expected client_secret in state to be preserved, got %q", state.ClientSecret.ValueString())
	}
}

func TestGoogleSsoProviderUpdateOmitsSecretWhenUnset(t *testing.T) {
	t.Parallel()

	plan := ssoProviderResourceModel{
		Name:         types.StringValue("Google Workspace"),
		ClientID:     types.StringValue("google-client-id"),
		ClientSecret: types.StringValue("keep-existing-secret"),
	}

	req := buildSsoProviderUpdateRequest(plan, types.StringNull())
	if req.ClientSecret != nil {
		t.Fatalf("expected client_secret to be omitted from update payload when unset in config")
	}
}

func TestGoogleSsoProviderReadRemovesStateWhenNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/settings/sso/providers/26fd7f8d-4f9f-4e0f-a252-a86bb0f018f6" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		http.Error(w, `{"error":"sso provider not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	res := newGoogleSsoProviderResource()
	configurable, ok := res.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("resource does not implement configure")
	}
	configurable.Configure(context.Background(), resource.ConfigureRequest{ProviderData: newTestAPIClient(t, server)}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := googleSsoProviderSchema(t)
	state := tfsdk.State{Schema: schemaResp.Schema}
	stateValue := emptyGoogleSsoProviderModel()
	stateValue.ID = types.StringValue("26fd7f8d-4f9f-4e0f-a252-a86bb0f018f6")
	stateValue.Name = types.StringValue("Google Workspace")
	stateValue.ClientID = types.StringValue("google-client-id")
	diags := state.Set(ctx, stateValue)
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
		t.Fatalf("expected state to be removed after 404 read")
	}
}

func TestGoogleSsoProviderDeleteUsesProviderID(t *testing.T) {
	t.Parallel()

	var deletePath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("unexpected method %s", r.Method)
		}
		deletePath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	res := newGoogleSsoProviderResource()
	configurable, ok := res.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("resource does not implement configure")
	}
	configurable.Configure(context.Background(), resource.ConfigureRequest{ProviderData: newTestAPIClient(t, server)}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := googleSsoProviderSchema(t)
	state := tfsdk.State{Schema: schemaResp.Schema}
	stateValue := emptyGoogleSsoProviderModel()
	stateValue.ID = types.StringValue("26fd7f8d-4f9f-4e0f-a252-a86bb0f018f6")
	stateValue.Name = types.StringValue("google-provider-name")
	diags := state.Set(ctx, stateValue)
	if diags.HasError() {
		t.Fatalf("unexpected state diagnostics: %#v", diags)
	}

	req := resource.DeleteRequest{State: state}
	resp := resource.DeleteResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	res.Delete(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}
	if deletePath != "/api/v1/settings/sso/providers/26fd7f8d-4f9f-4e0f-a252-a86bb0f018f6" {
		t.Fatalf("expected delete by provider id, got path %q", deletePath)
	}
}

func TestProviderResourcesIncludeGoogleSsoProvider(t *testing.T) {
	t.Parallel()

	provider := New("test")()
	resources := provider.Resources(context.Background())
	if len(resources) == 0 {
		t.Fatalf("expected resource registrations")
	}

	var foundGoogle bool
	var foundServiceAccount bool
	var foundServiceAccountToken bool

	for _, factory := range resources {
		res := factory()
		var resp resource.MetadataResponse
		res.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "neuwerk"}, &resp)
		switch {
		case strings.HasSuffix(resp.TypeName, "_sso_provider_google"):
			foundGoogle = true
		case strings.HasSuffix(resp.TypeName, "_service_account"):
			foundServiceAccount = true
		case strings.HasSuffix(resp.TypeName, "_service_account_token"):
			foundServiceAccountToken = true
		}
	}

	if !foundGoogle {
		t.Fatalf("expected google sso provider resource registration")
	}
	if !foundServiceAccount {
		t.Fatalf("expected service account resource registration to remain")
	}
	if !foundServiceAccountToken {
		t.Fatalf("expected service account token resource registration to remain")
	}
}

func googleSsoProviderSchema(t *testing.T) resource.SchemaResponse {
	t.Helper()

	res := newGoogleSsoProviderResource()
	var resp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	return resp
}

func emptyGoogleSsoProviderModel() ssoProviderResourceModel {
	return ssoProviderResourceModel{
		Scopes:               types.SetNull(types.StringType),
		AdminSubjects:        types.SetNull(types.StringType),
		AdminGroups:          types.SetNull(types.StringType),
		AdminEmailDomains:    types.SetNull(types.StringType),
		ReadonlySubjects:     types.SetNull(types.StringType),
		ReadonlyGroups:       types.SetNull(types.StringType),
		ReadonlyEmailDomains: types.SetNull(types.StringType),
		AllowedEmailDomains:  types.SetNull(types.StringType),
	}
}

func setStringValues(values ...types.String) types.Set {
	set, diags := types.SetValueFrom(context.Background(), types.StringType, values)
	if diags.HasError() {
		panic("unexpected diagnostics constructing set")
	}
	return set
}

func assertStringSetElements(t *testing.T, got types.Set, want []string) {
	t.Helper()

	if got.IsNull() {
		t.Fatalf("expected set to be non-null")
	}
	if got.IsUnknown() {
		t.Fatalf("expected set to be known")
	}

	var elems []basetypes.StringValue
	diags := got.ElementsAs(context.Background(), &elems, false)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics decoding set: %#v", diags)
	}

	flattened := make([]string, 0, len(elems))
	for _, elem := range elems {
		flattened = append(flattened, elem.ValueString())
	}
	sort.Strings(flattened)

	expect := append([]string{}, want...)
	sort.Strings(expect)
	if !reflect.DeepEqual(flattened, expect) {
		t.Fatalf("unexpected set values: got %#v want %#v", flattened, expect)
	}
}
