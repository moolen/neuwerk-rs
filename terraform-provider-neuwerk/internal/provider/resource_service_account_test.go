package provider

import (
	"context"
	"reflect"
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

	res := newServiceAccountResource()
	var schemaResp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)

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
	var schemaResp resource.SchemaResponse
	res.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

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

func TestProviderResourcesIncludeServiceAccount(t *testing.T) {
	t.Parallel()

	provider := &neuwerkProvider{}
	resources := provider.Resources(context.Background())
	if !resourceFactoriesContain(resources, newServiceAccountResource) {
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
