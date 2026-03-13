package provider

import "github.com/hashicorp/terraform-plugin-framework/types"

func optionalStringValue(value *string) types.String {
	if value == nil {
		return types.StringNull()
	}
	return types.StringValue(*value)
}
