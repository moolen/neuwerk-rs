resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  name_suffix          = random_string.suffix.result
  name_prefix          = "${var.name_prefix}-${local.name_suffix}"
  storage_account_name = substr(replace(replace(lower("${var.name_prefix}${local.name_suffix}"), "-", ""), "_", ""), 0, 24)
}

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

module "network" {
  source                = "./modules/network"
  resource_group_name   = azurerm_resource_group.main.name
  location              = azurerm_resource_group.main.location
  vnet_cidr             = var.vnet_cidr
  mgmt_subnet_cidr      = var.mgmt_subnet_cidr
  dataplane_subnet_cidr = var.dataplane_subnet_cidr
  consumer_subnet_cidr  = var.consumer_subnet_cidr
  upstream_subnet_cidr  = var.upstream_subnet_cidr
  jumpbox_subnet_cidr   = var.jumpbox_subnet_cidr
  admin_cidr            = var.admin_cidr
  tags                  = var.tags
}

module "storage" {
  source               = "./modules/storage"
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  storage_account_name = local.storage_account_name
  container_name       = "firewall"
  firewall_binary_path = var.firewall_binary_path
  firewall_blob_name   = var.firewall_blob_name
  tags                 = var.tags
}

module "dataplane_lb" {
  source              = "./modules/dataplane_lb"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  name_prefix         = local.name_prefix
  subnet_id           = module.network.dataplane_subnet_id
  private_ip          = var.dataplane_lb_ip
  health_probe_port   = var.dataplane_lb_probe_port
  tags                = var.tags
}

module "upstream_lb" {
  source              = "./modules/upstream_lb"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  name_prefix         = local.name_prefix
  subnet_id           = module.network.upstream_subnet_id
  private_ip          = var.upstream_lb_ip
  tags                = var.tags
}

module "firewall_vmss" {
  source                       = "./modules/firewall_vmss"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  name_prefix                  = local.name_prefix
  instance_count               = var.firewall_instance_count
  vm_size                      = var.firewall_vmss_size
  admin_username               = var.admin_username
  ssh_public_key               = file(var.ssh_public_key_path)
  mgmt_subnet_id               = module.network.mgmt_subnet_id
  dataplane_subnet_id          = module.network.dataplane_subnet_id
  dataplane_lb_backend_pool_id = module.dataplane_lb.backend_pool_id
  dns_target_ips               = length(var.dns_target_ips) > 0 ? var.dns_target_ips : ["$${MGMT_IP}"]
  dns_upstreams                = length(var.dns_upstreams) > 0 ? var.dns_upstreams : ["${module.upstream_vm.private_ip}:53"]
  dns_zone_name                = var.dns_zone_name
  gwlb_vni_internal            = var.gwlb_vni_internal
  gwlb_vni_external            = var.gwlb_vni_external
  gwlb_udp_port_internal       = var.gwlb_udp_port_internal
  gwlb_udp_port_external       = var.gwlb_udp_port_external
  internal_cidr                = var.consumer_subnet_cidr
  snat_mode                    = var.firewall_snat_mode
  dpdk_workers                 = var.firewall_dpdk_workers
  storage_account_name         = module.storage.account_name
  storage_container_name       = module.storage.container_name
  storage_blob_name            = module.storage.blob_name
  azure_subscription_id        = var.subscription_id
  azure_resource_group         = azurerm_resource_group.main.name
  azure_vmss_name              = "${local.name_prefix}-fw"
  cloud_provider               = var.cloud_provider
  tags                         = var.tags
  firewall_image_id            = var.firewall_image_id
  image_publisher              = var.image_publisher
  image_offer                  = var.image_offer
  image_sku                    = var.image_sku
  image_version                = var.image_version
}

module "upstream_vm" {
  source                   = "./modules/upstream_vm"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  name_prefix              = local.name_prefix
  vm_size                  = var.upstream_vm_size
  admin_username           = var.admin_username
  ssh_public_key           = file(var.ssh_public_key_path)
  subnet_id                = module.network.upstream_subnet_id
  upstream_backend_pool_id = module.upstream_lb.backend_pool_id
  dns_zone_name            = var.dns_zone_name
  upstream_vip             = module.upstream_lb.private_ip
  tags                     = var.tags
  image_publisher          = var.image_publisher
  image_offer              = var.image_offer
  image_sku                = var.image_sku
  image_version            = var.image_version
}

module "consumer_vms" {
  source                     = "./modules/consumer_vms"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  name_prefix                = local.name_prefix
  vm_size                    = var.consumer_vm_size
  instance_count             = var.consumer_count
  secondary_private_ip_count = var.consumer_secondary_private_ip_count
  admin_username             = var.admin_username
  ssh_public_key             = file(var.ssh_public_key_path)
  subnet_id                  = module.network.consumer_subnet_id
  gwlb_frontend_id           = ""
  attach_gwlb                = var.consumer_attach_gwlb
  public_ip_enabled          = var.consumer_public_ip_enabled
  tags                       = var.tags
  image_publisher            = var.image_publisher
  image_offer                = var.image_offer
  image_sku                  = var.image_sku
  image_version              = var.image_version
}

module "jumpbox" {
  source              = "./modules/jumpbox"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  name_prefix         = local.name_prefix
  vm_size             = var.jumpbox_vm_size
  admin_username      = var.admin_username
  ssh_public_key      = file(var.ssh_public_key_path)
  subnet_id           = module.network.jumpbox_subnet_id
  tags                = var.tags
  image_publisher     = var.image_publisher
  image_offer         = var.image_offer
  image_sku           = var.image_sku
  image_version       = var.image_version
}

resource "azurerm_route_table" "consumer" {
  name                = "${local.name_prefix}-consumer-rt"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = var.tags
}

resource "azurerm_route" "consumer_to_upstream" {
  name                   = "consumer-to-upstream"
  resource_group_name    = azurerm_resource_group.main.name
  route_table_name       = azurerm_route_table.consumer.name
  address_prefix         = var.upstream_subnet_cidr
  next_hop_type          = "VirtualAppliance"
  next_hop_in_ip_address = module.dataplane_lb.private_ip
}

resource "azurerm_subnet_route_table_association" "consumer" {
  subnet_id      = module.network.consumer_subnet_id
  route_table_id = azurerm_route_table.consumer.id
}

resource "azurerm_route_table" "upstream" {
  name                = "${local.name_prefix}-upstream-rt"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = var.tags
}

resource "azurerm_route" "upstream_to_consumer" {
  name                   = "upstream-to-consumer"
  resource_group_name    = azurerm_resource_group.main.name
  route_table_name       = azurerm_route_table.upstream.name
  address_prefix         = var.consumer_subnet_cidr
  next_hop_type          = "VirtualAppliance"
  next_hop_in_ip_address = module.dataplane_lb.private_ip
}

resource "azurerm_subnet_route_table_association" "upstream" {
  subnet_id      = module.network.upstream_subnet_id
  route_table_id = azurerm_route_table.upstream.id
}

resource "azurerm_role_assignment" "firewall_blob_reader" {
  scope                = module.storage.account_id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = module.firewall_vmss.identity_principal_id
}

resource "azurerm_role_assignment" "firewall_network_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Network Contributor"
  principal_id         = module.firewall_vmss.identity_principal_id
}

resource "azurerm_role_assignment" "firewall_reader" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = module.firewall_vmss.identity_principal_id
}
