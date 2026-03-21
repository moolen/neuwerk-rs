package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestServiceAccountStateFromAPI(t *testing.T) {
	t.Parallel()

	record := &apiServiceAccount{
		ID:          "acc-1",
		Name:        "ci-bot",
		Description: nil,
		CreatedAt:   "2024-01-01T00:00:00Z",
		CreatedBy:   "admin",
		Role:        "admin",
		Status:      "active",
	}

	state := serviceAccountStateFromAPI(serviceAccountResourceModel{}, record)

	if state.ID.ValueString() != "acc-1" {
		t.Fatalf("unexpected id %q", state.ID.ValueString())
	}
	if state.Name.ValueString() != "ci-bot" {
		t.Fatalf("unexpected name %q", state.Name.ValueString())
	}
	if !state.Description.IsNull() {
		t.Fatalf("expected null description, got %q", state.Description.ValueString())
	}
	if state.CreatedAt.ValueString() != "2024-01-01T00:00:00Z" {
		t.Fatalf("unexpected created_at %q", state.CreatedAt.ValueString())
	}
	if state.CreatedBy.ValueString() != "admin" {
		t.Fatalf("unexpected created_by %q", state.CreatedBy.ValueString())
	}
	if state.Role.ValueString() != "admin" {
		t.Fatalf("unexpected role %q", state.Role.ValueString())
	}
	if state.Status.ValueString() != "active" {
		t.Fatalf("unexpected status %q", state.Status.ValueString())
	}
}

func TestParseServiceAccountImportIDRejectsEmptyValue(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	if _, ok := parseServiceAccountImportID("   ", &diags); ok {
		t.Fatalf("expected empty import id to be rejected")
	}
	if !diags.HasError() {
		t.Fatalf("expected diagnostics error")
	}
}

func TestServiceAccountSchema(t *testing.T) {
	t.Parallel()

	schemaResp := serviceAccountSchema(t)

	assertStringAttribute(t, schemaResp.Schema.Attributes, "name", true, false, false)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "description", false, true, false)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "role", true, false, false)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "id", false, false, true)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "created_at", false, false, true)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "created_by", false, false, true)
	assertStringAttribute(t, schemaResp.Schema.Attributes, "status", false, false, true)
}

func TestServiceAccountImportStateStoresID(t *testing.T) {
	t.Parallel()

	res := newServiceAccountResource()
	importable, ok := res.(resource.ResourceWithImportState)
	if !ok {
		t.Fatalf("resource does not implement import state")
	}
	ctx := context.Background()
	schemaResp := serviceAccountSchema(t)

	resp := resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema},
	}
	resp.State.Raw = tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)
	req := resource.ImportStateRequest{ID: "acc-123"}
	importable.ImportState(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}

	var got types.String
	resp.Diagnostics.Append(resp.State.GetAttribute(ctx, path.Root("id"), &got)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics after state read: %#v", resp.Diagnostics)
	}
	if got.ValueString() != "acc-123" {
		t.Fatalf("unexpected imported id %q", got.ValueString())
	}
}

func TestServiceAccountCreateRejectsBlankName(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaResp := serviceAccountSchema(t)

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	planValue := serviceAccountResourceModel{
		Name: types.StringValue("   "),
		Role: types.StringValue("admin"),
	}
	diags := plan.Set(ctx, planValue)
	if diags.HasError() {
		t.Fatalf("unexpected plan diagnostics: %#v", diags)
	}

	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}

	res := newServiceAccountResource().(resource.Resource)
	res.Create(ctx, req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected diagnostics error for blank name")
	}
}

func TestServiceAccountUpdateOmitsBlankDescription(t *testing.T) {
	t.Parallel()

	var sawDescription bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts/acc-1" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if _, ok := payload["description"]; ok {
			sawDescription = true
		}
		if payload["name"] != "ci-bot" {
			t.Fatalf("unexpected name %#v", payload["name"])
		}
		if payload["role"] != "admin" {
			t.Fatalf("unexpected role %#v", payload["role"])
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"acc-1","name":"ci-bot","description":null,"created_at":"2024-01-01T00:00:00Z","created_by":"admin","role":"admin","status":"active"}`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	res := newServiceAccountResource()
	configurable, ok := res.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("resource does not implement configure")
	}
	configurable.Configure(context.Background(), resource.ConfigureRequest{ProviderData: client}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := serviceAccountSchema(t)
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	planValue := serviceAccountResourceModel{
		ID:          types.StringValue("acc-1"),
		Name:        types.StringValue("ci-bot"),
		Description: types.StringValue("   "),
		Role:        types.StringValue("admin"),
	}
	diags := plan.Set(ctx, planValue)
	if diags.HasError() {
		t.Fatalf("unexpected plan diagnostics: %#v", diags)
	}

	req := resource.UpdateRequest{Plan: plan}
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}

	res.Update(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %#v", resp.Diagnostics)
	}
	if sawDescription {
		t.Fatalf("expected description to be omitted from request body")
	}

	var state serviceAccountResourceModel
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics reading state: %#v", resp.Diagnostics)
	}
	if state.ID.ValueString() != "acc-1" {
		t.Fatalf("unexpected state id %q", state.ID.ValueString())
	}
	if state.Description.IsNull() == false && strings.TrimSpace(state.Description.ValueString()) != "" {
		t.Fatalf("expected description to be null or blank, got %q", state.Description.ValueString())
	}
}

func TestServiceAccountReadRemovesStateWhenNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v1/service-accounts" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := newTestAPIClient(t, server)
	res := newServiceAccountResource()
	configurable, ok := res.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatalf("resource does not implement configure")
	}
	configurable.Configure(context.Background(), resource.ConfigureRequest{ProviderData: client}, &resource.ConfigureResponse{})

	ctx := context.Background()
	schemaResp := serviceAccountSchema(t)
	state := tfsdk.State{Schema: schemaResp.Schema}
	diags := state.Set(ctx, serviceAccountResourceModel{
		ID:     types.StringValue("acc-1"),
		Name:   types.StringValue("ci-bot"),
		Role:   types.StringValue("admin"),
		Status: types.StringValue("active"),
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
		t.Fatalf("expected state to be removed")
	}
}

func TestProviderResourcesIncludeServiceAccount(t *testing.T) {
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
		if strings.HasSuffix(resp.TypeName, "_service_account") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected service account resource registration")
	}
}

func resourceFactoriesContain(list []func() resource.Resource, target func() resource.Resource) bool {
	targetPtr := reflect.ValueOf(target).Pointer()
	for _, item := range list {
		if reflect.ValueOf(item).Pointer() == targetPtr {
			return true
		}
	}
	return false
}

func assertStringAttribute(t *testing.T, attrs map[string]resourceschema.Attribute, name string, required bool, optional bool, computed bool) {
	t.Helper()

	attr, ok := attrs[name]
	if !ok {
		t.Fatalf("missing attribute %q", name)
	}
	stringAttr, ok := attr.(resourceschema.StringAttribute)
	if !ok {
		t.Fatalf("attribute %q is not a string attribute", name)
	}
	if stringAttr.Required != required {
		t.Fatalf("attribute %q required=%v expected %v", name, stringAttr.Required, required)
	}
	if stringAttr.Optional != optional {
		t.Fatalf("attribute %q optional=%v expected %v", name, stringAttr.Optional, optional)
	}
	if stringAttr.Computed != computed {
		t.Fatalf("attribute %q computed=%v expected %v", name, stringAttr.Computed, computed)
	}
}

func serviceAccountSchema(t *testing.T) resource.SchemaResponse {
	t.Helper()

	res := newServiceAccountResource()
	var schemaResp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp
}
