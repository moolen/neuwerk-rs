package provider

import (
	"context"
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
		Token: types.StringValue("signed-token"),
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
