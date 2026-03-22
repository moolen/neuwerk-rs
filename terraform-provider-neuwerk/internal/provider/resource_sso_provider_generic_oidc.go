package provider

import "github.com/hashicorp/terraform-plugin-framework/resource"

var genericOidcSsoProviderKindConfig = ssoProviderKindConfig{
	kind:                     "generic-oidc",
	resourceTypeSuffix:       "sso_provider_generic_oidc",
	description:              "Manages a Generic OIDC SSO provider backed by the Neuwerk HTTP API.",
	requireExplicitEndpoints: true,
}

func newGenericOidcSsoProviderResource() resource.Resource {
	return newSsoProviderResource(genericOidcSsoProviderKindConfig)
}
