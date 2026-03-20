resource "azurerm_storage_account" "main" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  tags                     = var.tags
}

resource "azurerm_storage_container" "neuwerk" {
  name                  = var.container_name
  storage_account_id    = azurerm_storage_account.main.id
  container_access_type = "private"
}

resource "azurerm_storage_blob" "neuwerk" {
  name                   = var.neuwerk_blob_name
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.neuwerk.name
  type                   = "Block"
  source                 = var.neuwerk_binary_path
  content_md5            = filemd5(var.neuwerk_binary_path)
}
