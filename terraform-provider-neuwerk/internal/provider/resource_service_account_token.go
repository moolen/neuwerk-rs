package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*serviceAccountTokenResource)(nil)
	_ resource.ResourceWithConfigure   = (*serviceAccountTokenResource)(nil)
	_ resource.ResourceWithImportState = (*serviceAccountTokenResource)(nil)
)

type serviceAccountTokenResource struct {
	client *apiClient
}

type serviceAccountTokenResourceModel struct {
	ID               types.String `tfsdk:"id"`
	ServiceAccountID types.String `tfsdk:"service_account_id"`
	Name             types.String `tfsdk:"name"`
	TTL              types.String `tfsdk:"ttl"`
	Eternal          types.Bool   `tfsdk:"eternal"`
	Role             types.String `tfsdk:"role"`
	Token            types.String `tfsdk:"token"`
	CreatedAt        types.String `tfsdk:"created_at"`
	CreatedBy        types.String `tfsdk:"created_by"`
	ExpiresAt        types.String `tfsdk:"expires_at"`
	RevokedAt        types.String `tfsdk:"revoked_at"`
	LastUsedAt       types.String `tfsdk:"last_used_at"`
	Kid              types.String `tfsdk:"kid"`
	Status           types.String `tfsdk:"status"`
}

func newServiceAccountTokenResource() resource.Resource {
	return &serviceAccountTokenResource{}
}

func (r *serviceAccountTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account_token"
}

func (r *serviceAccountTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resourceschema.Schema{
		Description: "Mints and manages immutable service account tokens in the Neuwerk control plane.",
		Attributes: map[string]resourceschema.Attribute{
			"id": resourceschema.StringAttribute{
				Computed: true,
			},
			"service_account_id": resourceschema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": resourceschema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ttl": resourceschema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"eternal": resourceschema.BoolAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"role": resourceschema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"token": resourceschema.StringAttribute{
				Computed:  true,
				Sensitive: true,
			},
			"created_at": resourceschema.StringAttribute{
				Computed: true,
			},
			"created_by": resourceschema.StringAttribute{
				Computed: true,
			},
			"expires_at": resourceschema.StringAttribute{
				Computed: true,
			},
			"revoked_at": resourceschema.StringAttribute{
				Computed: true,
			},
			"last_used_at": resourceschema.StringAttribute{
				Computed: true,
			},
			"kid": resourceschema.StringAttribute{
				Computed: true,
			},
			"status": resourceschema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (r *serviceAccountTokenResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*apiClient)
}

func (r *serviceAccountTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceAccountTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	serviceAccountID, ok := trimServiceAccountTokenServiceAccountID(plan.ServiceAccountID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	if !validateServiceAccountTokenPlan(plan, &resp.Diagnostics) {
		return
	}
	plan.ServiceAccountID = types.StringValue(serviceAccountID)

	record, err := r.client.CreateServiceAccountToken(ctx, serviceAccountID, createServiceAccountTokenRequest{
		Name:    optionalTrimmedStringPointer(plan.Name),
		TTL:     optionalTrimmedStringPointer(plan.TTL),
		Eternal: optionalBoolPointer(plan.Eternal),
		Role:    optionalTrimmedStringPointer(plan.Role),
	})
	if err != nil {
		resp.Diagnostics.AddError("Create Service Account Token Failed", err.Error())
		return
	}

	state := serviceAccountTokenStateFromAPI(plan, &record.TokenMeta)
	state.Token = types.StringValue(record.Token)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceAccountTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceAccountTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tokens, err := r.client.ListServiceAccountTokens(ctx, state.ServiceAccountID.ValueString())
	if err != nil {
		if isNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read Service Account Token Failed", err.Error())
		return
	}

	record := findServiceAccountToken(tokens, state.ID.ValueString())
	if record == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	if record.Status == "revoked" {
		resp.State.RemoveResource(ctx)
		return
	}

	next := serviceAccountTokenStateFromAPI(state, record)
	if state.Name.IsNull() || state.Name.IsUnknown() {
		next.Name = optionalStringValue(record.Name)
	}
	if state.Role.IsNull() || state.Role.IsUnknown() {
		next.Role = types.StringValue(record.Role)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *serviceAccountTokenResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update Service Account Token Failed",
		"Service account tokens are immutable; replace the resource to mint a new token.",
	)
}

func (r *serviceAccountTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceAccountTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteServiceAccountToken(ctx, state.ServiceAccountID.ValueString(), state.ID.ValueString()); err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Delete Service Account Token Failed", err.Error())
	}
}

func (r *serviceAccountTokenResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	serviceAccountID, tokenID, ok := parseServiceAccountTokenImportID(req.ID, &resp.Diagnostics)
	if !ok {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service_account_id"), serviceAccountID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), tokenID)...)
}

func trimServiceAccountTokenServiceAccountID(value string, diags *diag.Diagnostics) (string, bool) {
	id := strings.TrimSpace(value)
	if id == "" {
		diags.AddAttributeError(
			path.Root("service_account_id"),
			"Invalid Service Account ID",
			"service_account_id must not be empty.",
		)
		return "", false
	}
	return id, true
}

func validateServiceAccountTokenPlan(plan serviceAccountTokenResourceModel, diags *diag.Diagnostics) bool {
	if plan.Eternal.IsNull() || plan.Eternal.IsUnknown() || !plan.Eternal.ValueBool() {
		return true
	}
	if plan.TTL.IsNull() || plan.TTL.IsUnknown() || strings.TrimSpace(plan.TTL.ValueString()) == "" {
		return true
	}

	diags.AddError("Invalid Service Account Token Configuration", "ttl cannot be set when eternal = true.")
	return false
}

func optionalTrimmedStringPointer(value types.String) *string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	trimmed := strings.TrimSpace(value.ValueString())
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func optionalBoolPointer(value types.Bool) *bool {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	parsed := value.ValueBool()
	return &parsed
}

func parseServiceAccountTokenImportID(raw string, diags *diag.Diagnostics) (string, string, bool) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) != 2 {
		diags.AddAttributeError(
			path.Root("id"),
			"Invalid Import ID",
			"Expected import ID in the form <service_account_id>/<token_id>.",
		)
		return "", "", false
	}

	serviceAccountID := strings.TrimSpace(parts[0])
	tokenID := strings.TrimSpace(parts[1])
	if serviceAccountID == "" || tokenID == "" {
		diags.AddAttributeError(
			path.Root("id"),
			"Invalid Import ID",
			"Expected import ID in the form <service_account_id>/<token_id>.",
		)
		return "", "", false
	}

	return serviceAccountID, tokenID, true
}

func findServiceAccountToken(tokens []apiServiceAccountTokenMeta, id string) *apiServiceAccountTokenMeta {
	for i := range tokens {
		if tokens[i].ID == id {
			return &tokens[i]
		}
	}
	return nil
}

func serviceAccountTokenStateFromAPI(prior serviceAccountTokenResourceModel, record *apiServiceAccountTokenMeta) serviceAccountTokenResourceModel {
	state := prior
	state.ID = types.StringValue(record.ID)
	state.CreatedAt = types.StringValue(record.CreatedAt)
	state.CreatedBy = types.StringValue(record.CreatedBy)
	state.ExpiresAt = optionalStringValue(record.ExpiresAt)
	state.RevokedAt = optionalStringValue(record.RevokedAt)
	state.LastUsedAt = optionalStringValue(record.LastUsedAt)
	state.Kid = types.StringValue(record.Kid)
	state.Status = types.StringValue(record.Status)
	return state
}
