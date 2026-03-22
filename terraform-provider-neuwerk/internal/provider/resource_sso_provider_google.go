package provider

import "github.com/hashicorp/terraform-plugin-framework/resource"

var googleSsoProviderKindConfig = ssoProviderKindConfig{
	kind:               "google",
	resourceTypeSuffix: "sso_provider_google",
	description:        "Manages a Google SSO provider backed by the Neuwerk HTTP API.",
}

func newGoogleSsoProviderResource() resource.Resource {
	return newSsoProviderResource(googleSsoProviderKindConfig)
}
