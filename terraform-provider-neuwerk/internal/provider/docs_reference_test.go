package provider

import (
	"os"
	"strings"
	"testing"
)

func TestTerraformDocsReferenceLayout(t *testing.T) {
	t.Parallel()

	resourceDocs := []string{
		"../../docs/resources/kubernetes_integration.md",
		"../../docs/resources/tls_intercept_ca.md",
		"../../docs/resources/service_account.md",
		"../../docs/resources/service_account_token.md",
		"../../docs/resources/sso_provider_google.md",
		"../../docs/resources/sso_provider_github.md",
		"../../docs/resources/sso_provider_generic_oidc.md",
	}

	for _, docPath := range resourceDocs {
		body := mustReadDoc(t, docPath)
		assertDocContains(t, docPath, body, "## Example Usage")
		assertDocContains(t, docPath, body, "## Argument Reference")
		assertDocContains(t, docPath, body, "## Attribute Reference")
		assertDocContains(t, docPath, body, "## Import")
	}

	indexBody := mustReadDoc(t, "../../docs/index.md")
	assertDocContains(t, "../../docs/index.md", indexBody, `source = "moolen/neuwerk"`)
	assertDocContains(t, "../../docs/index.md", indexBody, "moolen/terraform-provider-neuwerk")
	assertDocContains(t, "../../docs/index.md", indexBody, "## Quick Start")

	providerBody := mustReadDoc(t, "../../docs/provider.md")
	assertDocContains(t, "../../docs/provider.md", providerBody, `source = "moolen/neuwerk"`)
	assertDocContains(t, "../../docs/provider.md", providerBody, "## Example Usage")
	assertDocContains(t, "../../docs/provider.md", providerBody, "## Argument Reference")
	assertDocContains(t, "../../docs/provider.md", providerBody, "## Manual Install")
}

func mustReadDoc(t *testing.T, path string) string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func assertDocContains(t *testing.T, path, body, needle string) {
	t.Helper()

	if !strings.Contains(body, needle) {
		t.Fatalf("%s is missing %q", path, needle)
	}
}
