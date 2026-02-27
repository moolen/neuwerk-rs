resource "azurerm_lb" "dns" {
  name                = "${var.name_prefix}-mgmt-dns-lb"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Standard"
  tags                = var.tags

  frontend_ip_configuration {
    name                          = "mgmt-dns-fe"
    subnet_id                     = var.mgmt_subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.mgmt_dns_lb_ip
  }
}

resource "azurerm_lb_backend_address_pool" "dns" {
  name            = "${var.name_prefix}-mgmt-dns-backend"
  loadbalancer_id = azurerm_lb.dns.id
}

resource "azurerm_lb_probe" "dns" {
  name                = "${var.name_prefix}-mgmt-dns-probe"
  loadbalancer_id     = azurerm_lb.dns.id
  protocol            = "Tcp"
  port                = 8443
  interval_in_seconds = 5
  number_of_probes    = 2
}

resource "azurerm_lb_rule" "dns_udp" {
  name                           = "${var.name_prefix}-mgmt-dns-udp"
  loadbalancer_id                = azurerm_lb.dns.id
  protocol                       = "Udp"
  frontend_port                  = 53
  backend_port                   = 53
  frontend_ip_configuration_name = azurerm_lb.dns.frontend_ip_configuration[0].name
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.dns.id]
  probe_id                       = azurerm_lb_probe.dns.id
}
