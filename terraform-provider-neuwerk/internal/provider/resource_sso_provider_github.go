package provider

import "github.com/hashicorp/terraform-plugin-framework/resource"

var githubSsoProviderKindConfig = ssoProviderKindConfig{
	kind:               "github",
	resourceTypeSuffix: "sso_provider_github",
	description:        "Manages a GitHub SSO provider backed by the Neuwerk HTTP API.",
}

func newGithubSsoProviderResource() resource.Resource {
	return newSsoProviderResource(githubSsoProviderKindConfig)
}
