output "name" {
  value = azurerm_orchestrated_virtual_machine_scale_set.neuwerk.name
}

output "identity_principal_id" {
  value = azurerm_user_assigned_identity.neuwerk.principal_id
}
