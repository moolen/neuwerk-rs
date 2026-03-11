source "azure-arm" "ubuntu_2404_amd64" {
  client_id                            = var.azure_client_id
  client_secret                        = var.azure_client_secret
  managed_image_name                   = "${var.azure_managed_image_name_prefix}-${var.target}-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  managed_image_resource_group_name    = var.azure_managed_image_resource_group_name
  os_type                              = "Linux"
  image_offer                          = "ubuntu-24_04-lts"
  image_publisher                      = "Canonical"
  image_sku                            = "server"
  location                             = var.azure_location
  subscription_id                      = var.azure_subscription_id
  tenant_id                            = var.azure_tenant_id
  temporary_resource_group_name        = var.azure_build_resource_group_name
  vm_size                              = var.azure_vm_size
  azure_tags = {
    "neuwerk.io/target"   = var.target
    "neuwerk.io/revision" = var.git_revision
    "neuwerk.io/release"  = var.release_version
  }
}
