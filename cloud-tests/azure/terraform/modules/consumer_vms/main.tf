resource "azurerm_public_ip" "consumer" {
  count               = var.instance_count
  name                = "${var.name_prefix}-consumer-${count.index}-pip"
  resource_group_name = var.resource_group_name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "consumer" {
  count                          = var.instance_count
  name                           = "${var.name_prefix}-consumer-${count.index}-nic"
  resource_group_name            = var.resource_group_name
  location                       = var.location
  tags                           = var.tags
  accelerated_networking_enabled = true

  ip_configuration {
    name                                               = "primary"
    primary                                            = true
    subnet_id                                          = var.subnet_id
    private_ip_address_allocation                      = "Dynamic"
    public_ip_address_id                               = var.public_ip_enabled ? azurerm_public_ip.consumer[count.index].id : null
    gateway_load_balancer_frontend_ip_configuration_id = (var.attach_gwlb && var.public_ip_enabled) ? var.gwlb_frontend_id : null
  }

  dynamic "ip_configuration" {
    for_each = range(var.secondary_private_ip_count)

    content {
      name                          = "secondary-${ip_configuration.value + 1}"
      primary                       = false
      subnet_id                     = var.subnet_id
      private_ip_address_allocation = "Dynamic"
    }
  }
}

resource "azurerm_linux_virtual_machine" "consumer" {
  count               = var.instance_count
  name                = "${var.name_prefix}-consumer-${count.index}"
  resource_group_name = var.resource_group_name
  location            = var.location
  size                = var.vm_size
  admin_username      = var.admin_username
  tags                = var.tags

  network_interface_ids = [azurerm_network_interface.consumer[count.index].id]

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

  custom_data = base64encode(templatefile("${path.module}/../../cloud-init/consumer.yaml.tmpl", {
    secondary_private_ip_count = var.secondary_private_ip_count
  }))
}
