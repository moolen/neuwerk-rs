resource "azurerm_lb" "dataplane" {
  name                = "${var.name_prefix}-dataplane-lb"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Standard"
  tags                = var.tags

  frontend_ip_configuration {
    name                          = "dataplane-fe"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.private_ip
  }
}

resource "azurerm_lb_backend_address_pool" "dataplane" {
  name            = "${var.name_prefix}-dataplane-backend"
  loadbalancer_id = azurerm_lb.dataplane.id
}

resource "azurerm_lb_probe" "dataplane" {
  name                = "${var.name_prefix}-dataplane-probe"
  loadbalancer_id     = azurerm_lb.dataplane.id
  protocol            = "Tcp"
  port                = var.health_probe_port
  interval_in_seconds = 5
  number_of_probes    = 2
}

resource "azurerm_lb_rule" "dataplane" {
  name                           = "${var.name_prefix}-dataplane-haports"
  loadbalancer_id                = azurerm_lb.dataplane.id
  protocol                       = "All"
  frontend_port                  = 0
  backend_port                   = 0
  frontend_ip_configuration_name = "dataplane-fe"
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.dataplane.id]
  probe_id                       = azurerm_lb_probe.dataplane.id
  enable_floating_ip             = true
  disable_outbound_snat          = true
}
