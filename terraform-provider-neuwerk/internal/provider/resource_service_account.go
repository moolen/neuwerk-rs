package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*serviceAccountResource)(nil)
	_ resource.ResourceWithConfigure   = (*serviceAccountResource)(nil)
	_ resource.ResourceWithImportState = (*serviceAccountResource)(nil)
)

type serviceAccountResource struct {
	client *apiClient
}

type serviceAccountResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Role        types.String `tfsdk:"role"`
	CreatedAt   types.String `tfsdk:"created_at"`
	CreatedBy   types.String `tfsdk:"created_by"`
	Status      types.String `tfsdk:"status"`
}

func newServiceAccountResource() resource.Resource {
	return &serviceAccountResource{}
}

func (r *serviceAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (r *serviceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resourceschema.Schema{
		Description: "Manages a service account backed by the Neuwerk HTTP API.",
		Attributes: map[string]resourceschema.Attribute{
			"id": resourceschema.StringAttribute{
				Computed: true,
			},
			"name": resourceschema.StringAttribute{
				Required: true,
			},
			"description": resourceschema.StringAttribute{
				Optional: true,
			},
			"role": resourceschema.StringAttribute{
				Required: true,
			},
			"created_at": resourceschema.StringAttribute{
				Computed: true,
			},
			"created_by": resourceschema.StringAttribute{
				Computed: true,
			},
			"status": resourceschema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (r *serviceAccountResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*apiClient)
}

func (r *serviceAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceAccountResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name, ok := trimServiceAccountName(plan.Name.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	descPtr := serviceAccountDescriptionPointer(plan.Description)
	record, err := r.client.CreateServiceAccount(ctx, createServiceAccountRequest{
		Name:        name,
		Description: descPtr,
		Role:        plan.Role.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Create Service Account Failed", err.Error())
		return
	}

	state := serviceAccountStateFromAPI(plan, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceAccountResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record, err := r.client.GetServiceAccount(ctx, state.ID.ValueString())
	if err != nil {
		if isNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read Service Account Failed", err.Error())
		return
	}

	next := serviceAccountStateFromAPI(state, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *serviceAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan serviceAccountResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name, ok := trimServiceAccountName(plan.Name.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	descPtr := serviceAccountDescriptionPointer(plan.Description)
	record, err := r.client.UpdateServiceAccount(ctx, plan.ID.ValueString(), updateServiceAccountRequest{
		Name:        name,
		Description: descPtr,
		Role:        plan.Role.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Update Service Account Failed", err.Error())
		return
	}

	state := serviceAccountStateFromAPI(plan, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceAccountResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteServiceAccount(ctx, state.ID.ValueString()); err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Delete Service Account Failed", err.Error())
	}
}

func (r *serviceAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := parseServiceAccountImportID(req.ID, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func trimServiceAccountName(value string, diags *diag.Diagnostics) (string, bool) {
	name := strings.TrimSpace(value)
	if name == "" {
		diags.AddAttributeError(
			path.Root("name"),
			"Invalid Service Account Name",
			"name must not be empty.",
		)
		return "", false
	}
	return name, true
}

func serviceAccountDescriptionPointer(value types.String) *string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	trimmed := strings.TrimSpace(value.ValueString())
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func parseServiceAccountImportID(raw string, diags *diag.Diagnostics) (string, bool) {
	id := strings.TrimSpace(raw)
	if id == "" {
		diags.AddAttributeError(
			path.Root("id"),
			"Invalid Import ID",
			"An import ID is required for service accounts.",
		)
		return "", false
	}
	return id, true
}

func serviceAccountStateFromAPI(prior serviceAccountResourceModel, record *apiServiceAccount) serviceAccountResourceModel {
	state := prior
	state.ID = types.StringValue(record.ID)
	if prior.Name.IsNull() || prior.Name.IsUnknown() || strings.TrimSpace(prior.Name.ValueString()) != record.Name {
		state.Name = types.StringValue(record.Name)
	}
	if serviceAccountDescriptionEquivalent(prior.Description, record.Description) {
		state.Description = prior.Description
	} else {
		state.Description = optionalStringValue(record.Description)
	}
	state.Role = types.StringValue(record.Role)
	state.CreatedAt = types.StringValue(record.CreatedAt)
	state.CreatedBy = types.StringValue(record.CreatedBy)
	state.Status = types.StringValue(record.Status)
	return state
}

func serviceAccountDescriptionEquivalent(prior types.String, apiValue *string) bool {
	if prior.IsNull() || prior.IsUnknown() {
		return false
	}
	trimmedPrior := strings.TrimSpace(prior.ValueString())
	if trimmedPrior == "" && apiValue == nil {
		return true
	}
	if apiValue == nil {
		return false
	}
	return trimmedPrior == *apiValue
}
