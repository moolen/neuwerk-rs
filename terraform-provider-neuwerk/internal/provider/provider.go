package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = (*neuwerkProvider)(nil)

type neuwerkProvider struct {
	version string
}

type providerModel struct {
	Endpoints      types.List   `tfsdk:"endpoints"`
	Token          types.String `tfsdk:"token"`
	CACertPEM      types.String `tfsdk:"ca_cert_pem"`
	CACertFile     types.String `tfsdk:"ca_cert_file"`
	RequestTimeout types.String `tfsdk:"request_timeout"`
	RetryTimeout   types.String `tfsdk:"retry_timeout"`
	Headers        types.Map    `tfsdk:"headers"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &neuwerkProvider{version: version}
	}
}

func (p *neuwerkProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "neuwerk"
	resp.Version = p.version
}

func (p *neuwerkProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = providerschema.Schema{
		Description: "Terraform provider for the Neuwerk HTTP API.",
		Attributes: map[string]providerschema.Attribute{
			"endpoints": providerschema.ListAttribute{
				Description: "HTTPS base URLs for the Neuwerk API. Endpoints are tried in order.",
				ElementType: types.StringType,
				Required:    true,
			},
			"token": providerschema.StringAttribute{
				Description: "Bearer token used for API authentication. Service-account admin tokens are supported.",
				Required:    true,
				Sensitive:   true,
			},
			"ca_cert_pem": providerschema.StringAttribute{
				Description: "PEM-encoded CA certificate used to verify the Neuwerk API server.",
				Optional:    true,
			},
			"ca_cert_file": providerschema.StringAttribute{
				Description: "Path to a PEM-encoded CA certificate used to verify the Neuwerk API server.",
				Optional:    true,
			},
			"request_timeout": providerschema.StringAttribute{
				Description: "Per-request timeout using Go duration syntax such as 30s.",
				Optional:    true,
			},
			"retry_timeout": providerschema.StringAttribute{
				Description: "Maximum time spent retrying transient transport failures across endpoints.",
				Optional:    true,
			},
			"headers": providerschema.MapAttribute{
				Description: "Optional extra headers sent with every API request.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (p *neuwerkProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Endpoints.IsUnknown() || config.Token.IsUnknown() {
		return
	}

	endpoints, diags := listToStrings(ctx, config.Endpoints, path.Root("endpoints"))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if len(endpoints) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("endpoints"),
			"Missing API Endpoint",
			"At least one endpoint must be configured.",
		)
		return
	}

	token := strings.TrimSpace(config.Token.ValueString())
	if token == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("token"),
			"Missing API Token",
			"The provider requires a non-empty bearer token.",
		)
		return
	}

	requestTimeout, ok := parseDurationAttribute(config.RequestTimeout, 30*time.Second, path.Root("request_timeout"), &resp.Diagnostics)
	if !ok {
		return
	}
	retryTimeout, ok := parseDurationAttribute(config.RetryTimeout, 5*time.Second, path.Root("retry_timeout"), &resp.Diagnostics)
	if !ok {
		return
	}

	caCertPEM, ok := readCACertificate(config, &resp.Diagnostics)
	if !ok {
		return
	}

	headers := map[string]string{}
	if !config.Headers.IsNull() && !config.Headers.IsUnknown() {
		resp.Diagnostics.Append(config.Headers.ElementsAs(ctx, &headers, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	client, err := newAPIClient(apiClientConfig{
		endpoints:      endpoints,
		token:          token,
		caCertPEM:      caCertPEM,
		requestTimeout: requestTimeout,
		retryTimeout:   retryTimeout,
		headers:        headers,
	})
	if err != nil {
		resp.Diagnostics.AddError("Invalid Provider Configuration", err.Error())
		return
	}

	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *neuwerkProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newPolicyResource,
		newKubernetesIntegrationResource,
		newTLSInterceptCAResource,
		newServiceAccountResource,
	}
}

func (p *neuwerkProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func parseDurationAttribute(value types.String, fallback time.Duration, attrPath path.Path, diags *diag.Diagnostics) (time.Duration, bool) {
	if value.IsNull() || value.IsUnknown() {
		return fallback, true
	}

	parsed, err := time.ParseDuration(strings.TrimSpace(value.ValueString()))
	if err != nil {
		diags.AddAttributeError(
			attrPath,
			"Invalid Duration",
			fmt.Sprintf("Expected a Go duration string such as 30s: %v", err),
		)
		return 0, false
	}
	if parsed <= 0 {
		diags.AddAttributeError(attrPath, "Invalid Duration", "Duration must be greater than zero.")
		return 0, false
	}
	return parsed, true
}

func listToStrings(ctx context.Context, value types.List, attrPath path.Path) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var items []string

	if value.IsNull() || value.IsUnknown() {
		return items, diags
	}

	diags.Append(value.ElementsAs(ctx, &items, false)...)
	if diags.HasError() {
		return nil, diags
	}

	normalized := make([]string, 0, len(items))
	for idx, raw := range items {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			diags.AddAttributeError(
				attrPath.AtListIndex(idx),
				"Empty Endpoint",
				"Endpoint entries must not be empty.",
			)
			continue
		}
		normalized = append(normalized, trimmed)
	}

	return normalized, diags
}

func readCACertificate(config providerModel, diags *diag.Diagnostics) ([]byte, bool) {
	pemValue := strings.TrimSpace(config.CACertPEM.ValueString())
	fileValue := strings.TrimSpace(config.CACertFile.ValueString())

	if pemValue != "" && fileValue != "" {
		diags.AddAttributeError(
			path.Root("ca_cert_pem"),
			"Conflicting CA Configuration",
			"Only one of ca_cert_pem or ca_cert_file may be configured.",
		)
		return nil, false
	}

	if fileValue != "" {
		data, err := os.ReadFile(fileValue)
		if err != nil {
			diags.AddAttributeError(
				path.Root("ca_cert_file"),
				"Unreadable CA File",
				fmt.Sprintf("Failed to read CA certificate file: %v", err),
			)
			return nil, false
		}
		pemValue = string(data)
	}

	if pemValue == "" {
		return nil, true
	}

	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		diags.AddAttributeError(
			path.Root("ca_cert_pem"),
			"Invalid CA Certificate",
			"CA certificate must be valid PEM.",
		)
		return nil, false
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		diags.AddAttributeError(
			path.Root("ca_cert_pem"),
			"Invalid CA Certificate",
			fmt.Sprintf("Failed to parse CA certificate: %v", err),
		)
		return nil, false
	}

	return []byte(pemValue), true
}

func normalizeEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("endpoint %q must use https", raw)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("endpoint %q must include a host", raw)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}
