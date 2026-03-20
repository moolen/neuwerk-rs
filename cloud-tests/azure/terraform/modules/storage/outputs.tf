output "account_name" {
  value = azurerm_storage_account.main.name
}

output "account_id" {
  value = azurerm_storage_account.main.id
}

output "container_name" {
  value = azurerm_storage_container.neuwerk.name
}

output "blob_name" {
  value = azurerm_storage_blob.neuwerk.name
}
