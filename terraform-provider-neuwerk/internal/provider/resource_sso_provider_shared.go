package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*ssoProviderResource)(nil)
	_ resource.ResourceWithConfigure   = (*ssoProviderResource)(nil)
	_ resource.ResourceWithImportState = (*ssoProviderResource)(nil)
)

type ssoProviderKindConfig struct {
	kind               string
	resourceTypeSuffix string
	description        string
}

type ssoProviderResource struct {
	client     *apiClient
	kindConfig ssoProviderKindConfig
}

type ssoProviderResourceModel struct {
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
	SessionTTLSecs       types.Int64  `tfsdk:"session_ttl_secs"`
	ID                   types.String `tfsdk:"id"`
	CreatedAt            types.String `tfsdk:"created_at"`
	UpdatedAt            types.String `tfsdk:"updated_at"`
}

type apiSsoProvider struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Kind                   string   `json:"kind"`
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

func newSsoProviderResource(kindConfig ssoProviderKindConfig) resource.Resource {
	return &ssoProviderResource{kindConfig: kindConfig}
}

func (r *ssoProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	suffix := strings.TrimSpace(r.kindConfig.resourceTypeSuffix)
	if suffix == "" {
		suffix = "sso_provider_" + strings.ReplaceAll(r.kindConfig.kind, "-", "_")
	}
	resp.TypeName = req.ProviderTypeName + "_" + suffix
}

func (r *ssoProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resourceschema.Schema{
		Description: r.kindConfig.description,
		Attributes: map[string]resourceschema.Attribute{
			"name": resourceschema.StringAttribute{
				Required: true,
			},
			"enabled": resourceschema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"display_order": resourceschema.Int64Attribute{
				Optional: true,
				Computed: true,
			},
			"issuer_url": resourceschema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"client_id": resourceschema.StringAttribute{
				Required: true,
			},
			"client_secret": resourceschema.StringAttribute{
				Optional:  true,
				Sensitive: true,
			},
			"scopes": resourceschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"pkce_required": resourceschema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"subject_claim": resourceschema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"email_claim": resourceschema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"groups_claim": resourceschema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"default_role": resourceschema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"admin_subjects": resourceschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"admin_groups": resourceschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"admin_email_domains": resourceschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"readonly_subjects": resourceschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"readonly_groups": resourceschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"readonly_email_domains": resourceschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"allowed_email_domains": resourceschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"authorization_url": resourceschema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"token_url": resourceschema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"userinfo_url": resourceschema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"session_ttl_secs": resourceschema.Int64Attribute{
				Optional: true,
				Computed: true,
			},
			"id": resourceschema.StringAttribute{
				Computed: true,
			},
			"created_at": resourceschema.StringAttribute{
				Computed: true,
			},
			"updated_at": resourceschema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (r *ssoProviderResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*apiClient)
}

func (r *ssoProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ssoProviderResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq, ok := buildSsoProviderCreateRequest(plan, r.kindConfig.kind, &resp.Diagnostics)
	if !ok {
		return
	}

	record, err := r.client.CreateSsoProvider(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Create SSO Provider Failed", err.Error())
		return
	}

	state := ssoProviderStateFromAPI(plan, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ssoProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ssoProviderResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record, err := r.client.GetSsoProvider(ctx, state.ID.ValueString())
	if err != nil {
		if isNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read SSO Provider Failed", err.Error())
		return
	}
	if err := validateSsoProviderKind(r.kindConfig.kind, record); err != nil {
		resp.Diagnostics.AddError("Read SSO Provider Failed", err.Error())
		return
	}

	next := ssoProviderStateFromAPI(state, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *ssoProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ssoProviderResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var prior ssoProviderResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var configClientSecret types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("client_secret"), &configClientSecret)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record, err := r.client.UpdateSsoProvider(ctx, plan.ID.ValueString(), buildSsoProviderUpdateRequest(plan, configClientSecret))
	if err != nil {
		resp.Diagnostics.AddError("Update SSO Provider Failed", err.Error())
		return
	}
	if err := validateSsoProviderKind(r.kindConfig.kind, record); err != nil {
		resp.Diagnostics.AddError("Update SSO Provider Failed", err.Error())
		return
	}

	stateInput := prior
	if nextSecret := configuredClientSecret(configClientSecret); nextSecret != nil {
		stateInput.ClientSecret = types.StringValue(*nextSecret)
	}

	state := ssoProviderStateFromAPI(stateInput, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ssoProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ssoProviderResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteSsoProvider(ctx, state.ID.ValueString()); err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Delete SSO Provider Failed", err.Error())
	}
}

func (r *ssoProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := parseSsoProviderImportID(req.ID, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func buildSsoProviderCreateRequest(plan ssoProviderResourceModel, kind string, diags *diag.Diagnostics) (createSsoProviderRequest, bool) {
	name := strings.TrimSpace(plan.Name.ValueString())
	if name == "" {
		diags.AddAttributeError(path.Root("name"), "Invalid SSO Provider Name", "name must not be empty.")
		return createSsoProviderRequest{}, false
	}

	clientID := strings.TrimSpace(plan.ClientID.ValueString())
	if clientID == "" {
		diags.AddAttributeError(path.Root("client_id"), "Invalid Client ID", "client_id must not be empty.")
		return createSsoProviderRequest{}, false
	}

	if plan.ClientSecret.IsNull() || plan.ClientSecret.IsUnknown() {
		diags.AddAttributeError(path.Root("client_secret"), "Missing Client Secret", "client_secret is required when creating an SSO provider.")
		return createSsoProviderRequest{}, false
	}
	clientSecret := strings.TrimSpace(plan.ClientSecret.ValueString())
	if clientSecret == "" {
		diags.AddAttributeError(path.Root("client_secret"), "Invalid Client Secret", "client_secret must not be empty.")
		return createSsoProviderRequest{}, false
	}

	req := createSsoProviderRequest{
		Name:                 name,
		Kind:                 kind,
		ClientID:             clientID,
		ClientSecret:         &clientSecret,
		Enabled:              optionalBoolPointer(plan.Enabled),
		DisplayOrder:         optionalInt64Pointer(plan.DisplayOrder),
		IssuerURL:            optionalTrimmedStringPointer(plan.IssuerURL),
		AuthorizationURL:     optionalTrimmedStringPointer(plan.AuthorizationURL),
		TokenURL:             optionalTrimmedStringPointer(plan.TokenURL),
		UserinfoURL:          optionalTrimmedStringPointer(plan.UserinfoURL),
		Scopes:               ssoProviderSetToSortedStrings(plan.Scopes, diags),
		PKCERequired:         optionalBoolPointer(plan.PKCERequired),
		SubjectClaim:         optionalTrimmedStringPointer(plan.SubjectClaim),
		EmailClaim:           optionalTrimmedStringPointer(plan.EmailClaim),
		GroupsClaim:          optionalTrimmedStringPointer(plan.GroupsClaim),
		DefaultRole:          optionalTrimmedStringPointer(plan.DefaultRole),
		AdminSubjects:        ssoProviderSetToSortedStrings(plan.AdminSubjects, diags),
		AdminGroups:          ssoProviderSetToSortedStrings(plan.AdminGroups, diags),
		AdminEmailDomains:    ssoProviderSetToSortedStrings(plan.AdminEmailDomains, diags),
		ReadonlySubjects:     ssoProviderSetToSortedStrings(plan.ReadonlySubjects, diags),
		ReadonlyGroups:       ssoProviderSetToSortedStrings(plan.ReadonlyGroups, diags),
		ReadonlyEmailDomains: ssoProviderSetToSortedStrings(plan.ReadonlyEmailDomains, diags),
		AllowedEmailDomains:  ssoProviderSetToSortedStrings(plan.AllowedEmailDomains, diags),
		SessionTTLSecs:       optionalInt64Pointer(plan.SessionTTLSecs),
	}
	if diags.HasError() {
		return createSsoProviderRequest{}, false
	}
	return req, true
}

func buildSsoProviderUpdateRequest(plan ssoProviderResourceModel, configClientSecret types.String) updateSsoProviderRequest {
	req := updateSsoProviderRequest{
		Name:                 optionalTrimmedStringPointer(plan.Name),
		Enabled:              optionalBoolPointer(plan.Enabled),
		DisplayOrder:         optionalInt64Pointer(plan.DisplayOrder),
		IssuerURL:            optionalTrimmedStringPointer(plan.IssuerURL),
		AuthorizationURL:     optionalTrimmedStringPointer(plan.AuthorizationURL),
		TokenURL:             optionalTrimmedStringPointer(plan.TokenURL),
		UserinfoURL:          optionalTrimmedStringPointer(plan.UserinfoURL),
		ClientID:             optionalTrimmedStringPointer(plan.ClientID),
		Scopes:               ssoProviderSetToSortedStrings(plan.Scopes, &diag.Diagnostics{}),
		PKCERequired:         optionalBoolPointer(plan.PKCERequired),
		SubjectClaim:         optionalTrimmedStringPointer(plan.SubjectClaim),
		EmailClaim:           optionalTrimmedStringPointer(plan.EmailClaim),
		GroupsClaim:          optionalTrimmedStringPointer(plan.GroupsClaim),
		DefaultRole:          optionalTrimmedStringPointer(plan.DefaultRole),
		AdminSubjects:        ssoProviderSetToSortedStrings(plan.AdminSubjects, &diag.Diagnostics{}),
		AdminGroups:          ssoProviderSetToSortedStrings(plan.AdminGroups, &diag.Diagnostics{}),
		AdminEmailDomains:    ssoProviderSetToSortedStrings(plan.AdminEmailDomains, &diag.Diagnostics{}),
		ReadonlySubjects:     ssoProviderSetToSortedStrings(plan.ReadonlySubjects, &diag.Diagnostics{}),
		ReadonlyGroups:       ssoProviderSetToSortedStrings(plan.ReadonlyGroups, &diag.Diagnostics{}),
		ReadonlyEmailDomains: ssoProviderSetToSortedStrings(plan.ReadonlyEmailDomains, &diag.Diagnostics{}),
		AllowedEmailDomains:  ssoProviderSetToSortedStrings(plan.AllowedEmailDomains, &diag.Diagnostics{}),
		SessionTTLSecs:       optionalInt64Pointer(plan.SessionTTLSecs),
	}

	if !configClientSecret.IsNull() && !configClientSecret.IsUnknown() {
		secret := strings.TrimSpace(configClientSecret.ValueString())
		if secret != "" {
			req.ClientSecret = &secret
		}
	}

	return req
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
		return nil
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

func optionalInt64Pointer(value types.Int64) *int64 {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	out := value.ValueInt64()
	return &out
}

func configuredClientSecret(configClientSecret types.String) *string {
	if configClientSecret.IsNull() || configClientSecret.IsUnknown() {
		return nil
	}
	secret := strings.TrimSpace(configClientSecret.ValueString())
	if secret == "" {
		return nil
	}
	return &secret
}

func validateSsoProviderKind(expected string, record *apiSsoProvider) error {
	got := strings.TrimSpace(record.Kind)
	if got == expected {
		return nil
	}
	return fmt.Errorf("kind mismatch for SSO provider %q: expected %q, got %q", record.ID, expected, got)
}
