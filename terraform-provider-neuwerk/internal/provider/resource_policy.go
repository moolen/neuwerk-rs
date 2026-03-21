package provider

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*policyResource)(nil)
	_ resource.ResourceWithConfigure   = (*policyResource)(nil)
	_ resource.ResourceWithImportState = (*policyResource)(nil)
)

type policyResource struct {
	client *apiClient
}

type policyResourceModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	CreatedAt     types.String `tfsdk:"created_at"`
	Mode          types.String `tfsdk:"mode"`
	DefaultAction types.String `tfsdk:"default_action"`
	DocumentJSON  types.String `tfsdk:"document_json"`
	SourceGroups  types.List   `tfsdk:"source_group"`
	CompiledJSON  types.String `tfsdk:"compiled_json"`
}

func newPolicyResource() resource.Resource {
	return &policyResource{}
}

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = resourceschema.Schema{
		Description: "Manages an aggregate policy document through the Neuwerk by-name policy API.",
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
			"mode": resourceschema.StringAttribute{
				Required: true,
			},
			"default_action": resourceschema.StringAttribute{
				Optional: true,
			},
			"document_json": resourceschema.StringAttribute{
				Optional:    true,
				Description: "Low-level policy JSON escape hatch. Mutually exclusive with nested source_group configuration.",
			},
			"source_group": resourceschema.ListNestedAttribute{
				Optional:    true,
				Description: "Higher-level nested policy authoring surface compiled into the current HTTP API policy document.",
				NestedObject: resourceschema.NestedAttributeObject{
					Attributes: map[string]resourceschema.Attribute{
						"id": resourceschema.StringAttribute{
							Required: true,
						},
						"priority": resourceschema.Int64Attribute{
							Optional: true,
						},
						"default_action": resourceschema.StringAttribute{
							Optional: true,
						},
						"sources": resourceschema.SingleNestedAttribute{
							Required: true,
							Attributes: map[string]resourceschema.Attribute{
								"cidrs": resourceschema.ListAttribute{
									Optional:    true,
									ElementType: types.StringType,
								},
								"ips": resourceschema.ListAttribute{
									Optional:    true,
									ElementType: types.StringType,
								},
								"kubernetes_selector": resourceschema.ListNestedAttribute{
									Optional: true,
									NestedObject: resourceschema.NestedAttributeObject{
										Attributes: map[string]resourceschema.Attribute{
											"integration": resourceschema.StringAttribute{
												Required: true,
											},
											"pod_selector": resourceschema.SingleNestedAttribute{
												Optional: true,
												Attributes: map[string]resourceschema.Attribute{
													"namespace": resourceschema.StringAttribute{
														Required: true,
													},
													"match_labels": resourceschema.MapAttribute{
														Optional:    true,
														ElementType: types.StringType,
													},
												},
											},
											"node_selector": resourceschema.SingleNestedAttribute{
												Optional: true,
												Attributes: map[string]resourceschema.Attribute{
													"match_labels": resourceschema.MapAttribute{
														Optional:    true,
														ElementType: types.StringType,
													},
												},
											},
										},
									},
								},
							},
						},
						"rule": resourceschema.ListNestedAttribute{
							Optional: true,
							NestedObject: resourceschema.NestedAttributeObject{
								Attributes: map[string]resourceschema.Attribute{
									"id": resourceschema.StringAttribute{
										Required: true,
									},
									"priority": resourceschema.Int64Attribute{
										Optional: true,
									},
									"action": resourceschema.StringAttribute{
										Required: true,
									},
									"mode": resourceschema.StringAttribute{
										Optional: true,
									},
									"dns": resourceschema.SingleNestedAttribute{
										Optional: true,
										Attributes: map[string]resourceschema.Attribute{
											"exact": resourceschema.ListAttribute{
												Optional:    true,
												ElementType: types.StringType,
											},
											"suffixes": resourceschema.ListAttribute{
												Optional:    true,
												ElementType: types.StringType,
											},
										},
									},
									"destination": resourceschema.SingleNestedAttribute{
										Optional: true,
										Attributes: map[string]resourceschema.Attribute{
											"protocol": resourceschema.StringAttribute{
												Optional: true,
											},
											"ports": resourceschema.ListAttribute{
												Optional:    true,
												ElementType: types.Int64Type,
											},
											"cidrs": resourceschema.ListAttribute{
												Optional:    true,
												ElementType: types.StringType,
											},
											"ips": resourceschema.ListAttribute{
												Optional:    true,
												ElementType: types.StringType,
											},
										},
									},
									"tls": resourceschema.SingleNestedAttribute{
										Optional: true,
										Attributes: map[string]resourceschema.Attribute{
											"mode": resourceschema.StringAttribute{
												Required: true,
											},
											"request": resourceschema.SingleNestedAttribute{
												Optional: true,
												Attributes: map[string]resourceschema.Attribute{
													"methods": resourceschema.ListAttribute{
														Optional:    true,
														ElementType: types.StringType,
													},
													"require_headers": resourceschema.ListAttribute{
														Optional:    true,
														ElementType: types.StringType,
													},
													"deny_headers": resourceschema.ListAttribute{
														Optional:    true,
														ElementType: types.StringType,
													},
													"target": resourceschema.ListNestedAttribute{
														Optional: true,
														NestedObject: resourceschema.NestedAttributeObject{
															Attributes: map[string]resourceschema.Attribute{
																"hosts": resourceschema.ListAttribute{
																	Required:    true,
																	ElementType: types.StringType,
																},
																"path_exact": resourceschema.ListAttribute{
																	Optional:    true,
																	ElementType: types.StringType,
																},
																"path_prefix": resourceschema.ListAttribute{
																	Optional:    true,
																	ElementType: types.StringType,
																},
																"path_regex": resourceschema.StringAttribute{
																	Optional: true,
																},
															},
														},
													},
												},
											},
											"response": resourceschema.SingleNestedAttribute{
												Optional: true,
												Attributes: map[string]resourceschema.Attribute{
													"deny_headers": resourceschema.ListAttribute{
														Optional:    true,
														ElementType: types.StringType,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"compiled_json": resourceschema.StringAttribute{
				Computed:    true,
				Description: "Canonical low-level policy JSON submitted to the HTTP API.",
			},
		},
	}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*apiClient)
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	state, ok := r.upsert(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record, err := r.client.GetPolicyByName(ctx, state.Name.ValueString())
	if err != nil {
		if isNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read Policy Failed", err.Error())
		return
	}

	compiledJSON, _, err := normalizeDocumentJSON(record.Policy)
	if err != nil {
		resp.Diagnostics.AddError("Read Policy Failed", err.Error())
		return
	}

	next := state
	next.ID = types.StringValue(record.ID)
	next.Name = types.StringValue(coalesceString(record.Name, state.Name.ValueString()))
	next.CreatedAt = types.StringValue(record.CreatedAt)
	next.Mode = types.StringValue(record.Mode)
	next.CompiledJSON = types.StringValue(compiledJSON)

	if strings.TrimSpace(state.DocumentJSON.ValueString()) != "" {
		next.DocumentJSON = state.DocumentJSON
	} else if state.SourceGroups.IsNull() && strings.TrimSpace(state.DefaultAction.ValueString()) == "" {
		next.DocumentJSON = types.StringValue(compiledJSON)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	state, ok := r.upsert(ctx, plan, &resp.Diagnostics)
	if !ok {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeletePolicy(ctx, state.ID.ValueString()); err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Delete Policy Failed", err.Error())
	}
}

func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func (r *policyResource) upsert(ctx context.Context, plan policyResourceModel, diags *diag.Diagnostics) (policyResourceModel, bool) {
	mode := strings.TrimSpace(plan.Mode.ValueString())
	if !isSupportedPolicyMode(mode) {
		diags.AddAttributeError(
			path.Root("mode"),
			"Invalid Policy Mode",
			"mode must be one of disabled, audit, or enforce.",
		)
		return policyResourceModel{}, false
	}

	compiledJSON, rawPolicy, sugarUsed, ok := buildPolicyPayload(ctx, plan, diags)
	if !ok {
		return policyResourceModel{}, false
	}

	record, err := r.client.UpsertPolicyByName(ctx, plan.Name.ValueString(), upsertPolicyByNameRequest{
		Mode:   mode,
		Name:   plan.Name.ValueString(),
		Policy: rawPolicy,
	})
	if err != nil {
		diags.AddError("Apply Policy Failed", err.Error())
		return policyResourceModel{}, false
	}

	state := plan
	state.ID = types.StringValue(record.ID)
	state.Name = types.StringValue(coalesceString(record.Name, plan.Name.ValueString()))
	state.CreatedAt = types.StringValue(record.CreatedAt)
	state.Mode = types.StringValue(record.Mode)
	state.CompiledJSON = types.StringValue(compiledJSON)
	if sugarUsed {
		state.DocumentJSON = types.StringNull()
	}

	return state, true
}

func buildPolicyPayload(ctx context.Context, plan policyResourceModel, diags *diag.Diagnostics) (string, json.RawMessage, bool, bool) {
	documentJSON := strings.TrimSpace(plan.DocumentJSON.ValueString())
	sugarConfigured := !plan.SourceGroups.IsNull() || strings.TrimSpace(plan.DefaultAction.ValueString()) != ""

	if documentJSON != "" && sugarConfigured {
		diags.AddError(
			"Conflicting Policy Configuration",
			"document_json cannot be combined with default_action or source_group nested configuration.",
		)
		return "", nil, false, false
	}

	if documentJSON != "" {
		normalized, rawPolicy, err := normalizeDocumentJSON([]byte(documentJSON))
		if err != nil {
			diags.AddAttributeError(path.Root("document_json"), "Invalid Policy JSON", err.Error())
			return "", nil, false, false
		}
		return normalized, rawPolicy, false, true
	}

	input, inputDiags := policyInputFromModel(ctx, plan)
	diags.Append(inputDiags...)
	if diags.HasError() {
		return "", nil, true, false
	}

	normalized, rawPolicy, err := compileSugarPolicy(input)
	if err != nil {
		diags.AddError("Invalid Policy Configuration", err.Error())
		return "", nil, true, false
	}

	return normalized, rawPolicy, true, true
}

func isSupportedPolicyMode(mode string) bool {
	switch strings.ToLower(mode) {
	case "disabled", "audit", "enforce":
		return true
	default:
		return false
	}
}

func normalizeDocumentJSON(raw []byte) (string, json.RawMessage, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", nil, err
	}
	canonical, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", nil, err
	}
	return string(canonical), json.RawMessage(canonical), nil
}

func coalesceString(value *string, fallback string) string {
	if value == nil || strings.TrimSpace(*value) == "" {
		return fallback
	}
	return *value
}
