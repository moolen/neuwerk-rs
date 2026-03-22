package provider

import (
	"context"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ssoProviderKindConfig struct {
	kind        string
	description string
}

type ssoProviderResourceModel struct {
	Name                types.String `tfsdk:"name"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	DisplayOrder        types.Int64  `tfsdk:"display_order"`
	IssuerURL           types.String `tfsdk:"issuer_url"`
	ClientID            types.String `tfsdk:"client_id"`
	ClientSecret        types.String `tfsdk:"client_secret"`
	Scopes              types.Set    `tfsdk:"scopes"`
	PKCERequired        types.Bool   `tfsdk:"pkce_required"`
	SubjectClaim        types.String `tfsdk:"subject_claim"`
	EmailClaim          types.String `tfsdk:"email_claim"`
	GroupsClaim         types.String `tfsdk:"groups_claim"`
	DefaultRole         types.String `tfsdk:"default_role"`
	AdminSubjects       types.Set    `tfsdk:"admin_subjects"`
	AdminGroups         types.Set    `tfsdk:"admin_groups"`
	AdminEmailDomains   types.Set    `tfsdk:"admin_email_domains"`
	ReadonlySubjects    types.Set    `tfsdk:"readonly_subjects"`
	ReadonlyGroups      types.Set    `tfsdk:"readonly_groups"`
	ReadonlyEmailDomains types.Set    `tfsdk:"readonly_email_domains"`
	AllowedEmailDomains types.Set    `tfsdk:"allowed_email_domains"`
	AuthorizationURL    types.String `tfsdk:"authorization_url"`
	TokenURL            types.String `tfsdk:"token_url"`
	UserinfoURL         types.String `tfsdk:"userinfo_url"`
	SessionTTLSecs      types.Int64  `tfsdk:"session_ttl_secs"`
	ID                  types.String `tfsdk:"id"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
}

type apiSsoProvider struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Enabled                bool     `json:"enabled"`
	DisplayOrder           int64    `json:"display_order"`
	IssuerURL              string   `json:"issuer_url"`
	ClientID               string   `json:"client_id"`
	ClientSecretConfigured bool     `json:"client_secret_configured"`
	Scopes                 []string `json:"scopes"`
	PKCERequired           bool     `json:"pkce_required"`
	SubjectClaim           string   `json:"subject_claim"`
	EmailClaim             string   `json:"email_claim"`
	GroupsClaim            string   `json:"groups_claim"`
	DefaultRole            *string  `json:"default_role"`
	AdminSubjects          []string `json:"admin_subjects"`
	AdminGroups            []string `json:"admin_groups"`
	AdminEmailDomains      []string `json:"admin_email_domains"`
	ReadonlySubjects       []string `json:"readonly_subjects"`
	ReadonlyGroups         []string `json:"readonly_groups"`
	ReadonlyEmailDomains   []string `json:"readonly_email_domains"`
	AllowedEmailDomains    []string `json:"allowed_email_domains"`
	AuthorizationURL       *string  `json:"authorization_url"`
	TokenURL               *string  `json:"token_url"`
	UserinfoURL            *string  `json:"userinfo_url"`
	SessionTTLSecs         int64    `json:"session_ttl_secs"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
}

func parseSsoProviderImportID(raw string, diags *diag.Diagnostics) (string, bool) {
	id := strings.TrimSpace(raw)
	if id == "" {
		diags.AddAttributeError(
			path.Root("id"),
			"Invalid Import ID",
			"An import ID is required for SSO providers.",
		)
		return "", false
	}
	return id, true
}

func ssoProviderStateFromAPI(prior ssoProviderResourceModel, record *apiSsoProvider) ssoProviderResourceModel {
	state := prior

	state.Name = types.StringValue(record.Name)
	state.Enabled = types.BoolValue(record.Enabled)
	state.DisplayOrder = types.Int64Value(record.DisplayOrder)
	state.IssuerURL = types.StringValue(record.IssuerURL)
	state.ClientID = types.StringValue(record.ClientID)
	state.Scopes = ssoProviderStringSetFromSlice(record.Scopes)
	state.PKCERequired = types.BoolValue(record.PKCERequired)
	state.SubjectClaim = types.StringValue(record.SubjectClaim)
	state.EmailClaim = types.StringValue(record.EmailClaim)
	state.GroupsClaim = types.StringValue(record.GroupsClaim)
	state.DefaultRole = optionalStringValue(record.DefaultRole)
	state.AdminSubjects = ssoProviderStringSetFromSlice(record.AdminSubjects)
	state.AdminGroups = ssoProviderStringSetFromSlice(record.AdminGroups)
	state.AdminEmailDomains = ssoProviderStringSetFromSlice(record.AdminEmailDomains)
	state.ReadonlySubjects = ssoProviderStringSetFromSlice(record.ReadonlySubjects)
	state.ReadonlyGroups = ssoProviderStringSetFromSlice(record.ReadonlyGroups)
	state.ReadonlyEmailDomains = ssoProviderStringSetFromSlice(record.ReadonlyEmailDomains)
	state.AllowedEmailDomains = ssoProviderStringSetFromSlice(record.AllowedEmailDomains)
	state.AuthorizationURL = optionalStringValue(record.AuthorizationURL)
	state.TokenURL = optionalStringValue(record.TokenURL)
	state.UserinfoURL = optionalStringValue(record.UserinfoURL)
	state.SessionTTLSecs = types.Int64Value(record.SessionTTLSecs)
	state.ID = types.StringValue(record.ID)
	state.CreatedAt = types.StringValue(record.CreatedAt)
	state.UpdatedAt = types.StringValue(record.UpdatedAt)

	state.ClientSecret = ssoProviderSecretState(prior.ClientSecret, record.ClientSecretConfigured)
	return state
}

func ssoProviderSecretState(prior types.String, configured bool) types.String {
	if !configured {
		return types.StringNull()
	}
	if prior.IsNull() {
		return types.StringNull()
	}
	return prior
}

func ssoProviderSetToSortedStrings(value types.Set, diags *diag.Diagnostics) []string {
	if value.IsNull() || value.IsUnknown() {
		return []string{}
	}

	var elems []types.String
	diags.Append(value.ElementsAs(context.Background(), &elems, false)...)
	if diags.HasError() {
		return nil
	}

	out := make([]string, 0, len(elems))
	for _, elem := range elems {
		if elem.IsNull() || elem.IsUnknown() {
			continue
		}
		out = append(out, elem.ValueString())
	}

	sort.Strings(out)
	return uniqueStrings(out)
}

func ssoProviderStringSetFromSlice(values []string) types.Set {
	if len(values) == 0 {
		return types.SetValueMust(types.StringType, []attr.Value{})
	}

	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	sorted = uniqueStrings(sorted)

	items := make([]attr.Value, 0, len(sorted))
	for _, value := range sorted {
		items = append(items, types.StringValue(value))
	}
	return types.SetValueMust(types.StringType, items)
}

func uniqueStrings(sorted []string) []string {
	if len(sorted) < 2 {
		return sorted
	}

	result := sorted[:1]
	for _, value := range sorted[1:] {
		if value == result[len(result)-1] {
			continue
		}
		result = append(result, value)
	}
	return result
}
