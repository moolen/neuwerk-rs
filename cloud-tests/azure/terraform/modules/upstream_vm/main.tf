resource "azurerm_network_interface" "upstream" {
  name                           = "${var.name_prefix}-upstream-nic"
  resource_group_name            = var.resource_group_name
  location                       = var.location
  tags                           = var.tags
  accelerated_networking_enabled = true

  ip_configuration {
    name                          = "primary"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_backend_address_pool_association" "upstream" {
  network_interface_id    = azurerm_network_interface.upstream.id
  ip_configuration_name   = azurerm_network_interface.upstream.ip_configuration[0].name
  backend_address_pool_id = var.upstream_backend_pool_id
}

resource "azurerm_linux_virtual_machine" "upstream" {
  name                = "${var.name_prefix}-upstream"
  resource_group_name = var.resource_group_name
  location            = var.location
  size                = var.vm_size
  admin_username      = var.admin_username
  tags                = var.tags

  network_interface_ids = [azurerm_network_interface.upstream.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  source_image_reference {
    publisher = var.image_publisher
    offer     = var.image_offer
    sku       = var.image_sku
    version   = var.image_version
  }

  os_disk {
    storage_account_type = "Premium_LRS"
    caching              = "ReadWrite"
  }

  custom_data = base64encode(templatefile("${path.module}/../../cloud-init/upstream.yaml.tmpl", {
    dns_zone_name    = var.dns_zone_name
    upstream_ip_addr = var.upstream_vip
  }))
}
