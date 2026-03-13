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
	_ resource.Resource                = (*tlsInterceptCAResource)(nil)
	_ resource.ResourceWithConfigure   = (*tlsInterceptCAResource)(nil)
	_ resource.ResourceWithImportState = (*tlsInterceptCAResource)(nil)
)

const tlsInterceptCAResourceID = "tls-intercept-ca"

type tlsInterceptCAResource struct {
	client *apiClient
}

type tlsInterceptCAResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Generate          types.Bool   `tfsdk:"generate"`
	CACertPEM         types.String `tfsdk:"ca_cert_pem"`
	CAKeyPEM          types.String `tfsdk:"ca_key_pem"`
	CAKeyDERB64       types.String `tfsdk:"ca_key_der_b64"`
	Configured        types.Bool   `tfsdk:"configured"`
	Source            types.String `tfsdk:"source"`
	FingerprintSHA256 types.String `tfsdk:"fingerprint_sha256"`
}

func newTLSInterceptCAResource() resource.Resource {
	return &tlsInterceptCAResource{}
}

func (r *tlsInterceptCAResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tls_intercept_ca"
}

func (r *tlsInterceptCAResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resourceschema.Schema{
		Description: "Manages the singleton TLS intercept CA setting in the Neuwerk control plane.",
		Attributes: map[string]resourceschema.Attribute{
			"id": resourceschema.StringAttribute{
				Computed: true,
			},
			"generate": resourceschema.BoolAttribute{
				Optional: true,
			},
			"ca_cert_pem": resourceschema.StringAttribute{
				Optional: true,
			},
			"ca_key_pem": resourceschema.StringAttribute{
				Optional:  true,
				Sensitive: true,
			},
			"ca_key_der_b64": resourceschema.StringAttribute{
				Optional:  true,
				Sensitive: true,
			},
			"configured": resourceschema.BoolAttribute{
				Computed: true,
			},
			"source": resourceschema.StringAttribute{
				Computed: true,
			},
			"fingerprint_sha256": resourceschema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (r *tlsInterceptCAResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*apiClient)
}

func (r *tlsInterceptCAResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tlsInterceptCAResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	status, ok := r.apply(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}

	state := tlsInterceptCAStateFromAPI(plan, status)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *tlsInterceptCAResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state tlsInterceptCAResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	status, err := r.client.GetTLSInterceptCA(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Read TLS Intercept CA Failed", err.Error())
		return
	}

	next := tlsInterceptCAStateFromAPI(state, status)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *tlsInterceptCAResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tlsInterceptCAResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	status, ok := r.apply(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}

	state := tlsInterceptCAStateFromAPI(plan, status)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *tlsInterceptCAResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.DeleteTLSInterceptCA(ctx); err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Delete TLS Intercept CA Failed", err.Error())
	}
}

func (r *tlsInterceptCAResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), tlsInterceptCAResourceID)...)
}

func (r *tlsInterceptCAResource) apply(ctx context.Context, plan tlsInterceptCAResourceModel, diags *diag.Diagnostics) (*apiTLSInterceptCAStatus, bool) {
	generate := !plan.Generate.IsNull() && !plan.Generate.IsUnknown() && plan.Generate.ValueBool()
	cert := strings.TrimSpace(plan.CACertPEM.ValueString())
	keyPEM := strings.TrimSpace(plan.CAKeyPEM.ValueString())
	keyDERB64 := strings.TrimSpace(plan.CAKeyDERB64.ValueString())

	switch {
	case generate && (cert != "" || keyPEM != "" || keyDERB64 != ""):
		diags.AddError("Invalid TLS Intercept CA Configuration", "generate cannot be combined with uploaded certificate or key material.")
		return nil, false
	case !generate && cert == "":
		diags.AddError("Invalid TLS Intercept CA Configuration", "Either generate = true or ca_cert_pem with key material must be configured.")
		return nil, false
	case keyPEM != "" && keyDERB64 != "":
		diags.AddError("Invalid TLS Intercept CA Configuration", "Only one of ca_key_pem or ca_key_der_b64 may be configured.")
		return nil, false
	case !generate && keyPEM == "" && keyDERB64 == "":
		diags.AddError("Invalid TLS Intercept CA Configuration", "Uploaded CA material requires either ca_key_pem or ca_key_der_b64.")
		return nil, false
	}

	var (
		status *apiTLSInterceptCAStatus
		err    error
	)

	if generate {
		status, err = r.client.GenerateTLSInterceptCA(ctx)
	} else {
		req := putTLSInterceptCARequest{
			CACertPEM: cert,
		}
		if keyPEM != "" {
			req.CAKeyPEM = &keyPEM
		}
		if keyDERB64 != "" {
			req.CAKeyDERB64 = &keyDERB64
		}
		status, err = r.client.PutTLSInterceptCA(ctx, req)
	}

	if err != nil {
		diags.AddError("Apply TLS Intercept CA Failed", err.Error())
		return nil, false
	}
	return status, true
}

func tlsInterceptCAStateFromAPI(prior tlsInterceptCAResourceModel, status *apiTLSInterceptCAStatus) tlsInterceptCAResourceModel {
	state := prior
	state.ID = types.StringValue(tlsInterceptCAResourceID)
	state.Configured = types.BoolValue(status.Configured)
	state.Source = optionalStringValue(status.Source)
	state.FingerprintSHA256 = optionalStringValue(status.FingerprintSHA256)
	return state
}
