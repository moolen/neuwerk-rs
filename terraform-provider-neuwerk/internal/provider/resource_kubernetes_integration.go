package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*kubernetesIntegrationResource)(nil)
	_ resource.ResourceWithConfigure   = (*kubernetesIntegrationResource)(nil)
	_ resource.ResourceWithImportState = (*kubernetesIntegrationResource)(nil)
)

type kubernetesIntegrationResource struct {
	client *apiClient
}

type kubernetesIntegrationResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	CreatedAt           types.String `tfsdk:"created_at"`
	Kind                types.String `tfsdk:"kind"`
	APIServerURL        types.String `tfsdk:"api_server_url"`
	CACertPEM           types.String `tfsdk:"ca_cert_pem"`
	ServiceAccountToken types.String `tfsdk:"service_account_token"`
	AuthType            types.String `tfsdk:"auth_type"`
	TokenConfigured     types.Bool   `tfsdk:"token_configured"`
}

func newKubernetesIntegrationResource() resource.Resource {
	return &kubernetesIntegrationResource{}
}

func (r *kubernetesIntegrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kubernetes_integration"
}

func (r *kubernetesIntegrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resourceschema.Schema{
		Description: "Manages a Kubernetes integration backed by the Neuwerk HTTP API.",
		Attributes: map[string]resourceschema.Attribute{
			"id": resourceschema.StringAttribute{
				Computed: true,
			},
			"name": resourceschema.StringAttribute{
				Required: true,
			},
			"created_at": resourceschema.StringAttribute{
				Computed: true,
			},
			"kind": resourceschema.StringAttribute{
				Computed: true,
			},
			"api_server_url": resourceschema.StringAttribute{
				Required: true,
			},
			"ca_cert_pem": resourceschema.StringAttribute{
				Required: true,
			},
			"service_account_token": resourceschema.StringAttribute{
				Required:  true,
				Sensitive: true,
			},
			"auth_type": resourceschema.StringAttribute{
				Computed: true,
			},
			"token_configured": resourceschema.BoolAttribute{
				Computed: true,
			},
		},
	}
}

func (r *kubernetesIntegrationResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*apiClient)
}

func (r *kubernetesIntegrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan kubernetesIntegrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record, err := r.client.CreateIntegration(ctx, createIntegrationRequest{
		Name:                plan.Name.ValueString(),
		Kind:                "kubernetes",
		APIServerURL:        plan.APIServerURL.ValueString(),
		CACertPEM:           plan.CACertPEM.ValueString(),
		ServiceAccountToken: plan.ServiceAccountToken.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Create Kubernetes Integration Failed", err.Error())
		return
	}

	state := integrationStateFromAPI(plan, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *kubernetesIntegrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state kubernetesIntegrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record, err := r.client.GetIntegration(ctx, state.Name.ValueString())
	if err != nil {
		if isNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read Kubernetes Integration Failed", err.Error())
		return
	}

	next := integrationStateFromAPI(state, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *kubernetesIntegrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan kubernetesIntegrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record, err := r.client.UpdateIntegration(ctx, plan.Name.ValueString(), updateIntegrationRequest{
		APIServerURL:        plan.APIServerURL.ValueString(),
		CACertPEM:           plan.CACertPEM.ValueString(),
		ServiceAccountToken: plan.ServiceAccountToken.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Update Kubernetes Integration Failed", err.Error())
		return
	}

	state := integrationStateFromAPI(plan, record)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *kubernetesIntegrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state kubernetesIntegrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteIntegration(ctx, state.Name.ValueString()); err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Delete Kubernetes Integration Failed", err.Error())
	}
}

func (r *kubernetesIntegrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func integrationStateFromAPI(prior kubernetesIntegrationResourceModel, record *apiIntegrationView) kubernetesIntegrationResourceModel {
	return kubernetesIntegrationResourceModel{
		ID:                  types.StringValue(record.ID),
		Name:                types.StringValue(record.Name),
		CreatedAt:           types.StringValue(record.CreatedAt),
		Kind:                types.StringValue(record.Kind),
		APIServerURL:        types.StringValue(record.APIServerURL),
		CACertPEM:           types.StringValue(record.CACertPEM),
		ServiceAccountToken: prior.ServiceAccountToken,
		AuthType:            types.StringValue(record.AuthType),
		TokenConfigured:     types.BoolValue(record.TokenConfigured),
	}
}
