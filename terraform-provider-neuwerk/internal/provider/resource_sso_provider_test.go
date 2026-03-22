package provider

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
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
