package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestServiceAccountStateFromAPI(t *testing.T) {
	t.Parallel()

	record := &apiServiceAccount{
		ID:          "acc-1",
		Name:        "ci-bot",
		Description: nil,
		CreatedAt:   "2024-01-01T00:00:00Z",
		CreatedBy:   "admin",
		Role:        "admin",
		Status:      "active",
	}

	state := serviceAccountStateFromAPI(serviceAccountResourceModel{}, record)

	if state.ID.ValueString() != "acc-1" {
		t.Fatalf("unexpected id %q", state.ID.ValueString())
	}
	if state.Name.ValueString() != "ci-bot" {
		t.Fatalf("unexpected name %q", state.Name.ValueString())
	}
	if !state.Description.IsNull() {
		t.Fatalf("expected null description, got %q", state.Description.ValueString())
	}
	if state.CreatedAt.ValueString() != "2024-01-01T00:00:00Z" {
		t.Fatalf("unexpected created_at %q", state.CreatedAt.ValueString())
	}
	if state.CreatedBy.ValueString() != "admin" {
		t.Fatalf("unexpected created_by %q", state.CreatedBy.ValueString())
	}
	if state.Role.ValueString() != "admin" {
		t.Fatalf("unexpected role %q", state.Role.ValueString())
	}
	if state.Status.ValueString() != "active" {
		t.Fatalf("unexpected status %q", state.Status.ValueString())
	}
}

func TestParseServiceAccountImportIDRejectsEmptyValue(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	if _, ok := parseServiceAccountImportID("   ", &diags); ok {
		t.Fatalf("expected empty import id to be rejected")
	}
	if !diags.HasError() {
		t.Fatalf("expected diagnostics error")
	}
}

func TestProviderResourcesIncludeServiceAccount(t *testing.T) {
	t.Parallel()

	provider := &neuwerkProvider{}
	resources := provider.Resources(context.Background())
	if !resourceFactoriesContain(resources, newServiceAccountResource) {
		t.Fatalf("expected service account resource registration")
	}
}

func resourceFactoriesContain(list []func() resource.Resource, target func() resource.Resource) bool {
	targetPtr := reflect.ValueOf(target).Pointer()
	for _, item := range list {
		if reflect.ValueOf(item).Pointer() == targetPtr {
			return true
		}
	}
	return false
}
