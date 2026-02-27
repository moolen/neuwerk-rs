locals {
  upstream_rules = {
    "tcp-80"   = { protocol = "Tcp", port = 80 }
    "tcp-443"  = { protocol = "Tcp", port = 443 }
    "tcp-9000" = { protocol = "Tcp", port = 9000 }
    "tcp-5201" = { protocol = "Tcp", port = 5201 }
    "udp-5201" = { protocol = "Udp", port = 5201 }
    "tcp-53"   = { protocol = "Tcp", port = 53 }
    "udp-53"   = { protocol = "Udp", port = 53 }
  }
}

resource "azurerm_lb" "upstream" {
  name                = "${var.name_prefix}-upstream-ilb"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Standard"
  tags                = var.tags

  frontend_ip_configuration {
    name                          = "upstream-fe"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.private_ip
  }
}

resource "azurerm_lb_backend_address_pool" "upstream" {
  name            = "${var.name_prefix}-upstream-backend"
  loadbalancer_id = azurerm_lb.upstream.id
}

resource "azurerm_lb_probe" "upstream" {
  name                = "${var.name_prefix}-upstream-probe"
  loadbalancer_id     = azurerm_lb.upstream.id
  protocol            = "Tcp"
  port                = 80
  interval_in_seconds = 5
  number_of_probes    = 2
}

resource "azurerm_lb_rule" "upstream" {
  for_each                       = local.upstream_rules
  name                           = "${var.name_prefix}-upstream-${each.key}"
  loadbalancer_id                = azurerm_lb.upstream.id
  protocol                       = each.value.protocol
  frontend_port                  = each.value.port
  backend_port                   = each.value.port
  frontend_ip_configuration_name = "upstream-fe"
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.upstream.id]
  probe_id                       = azurerm_lb_probe.upstream.id
  enable_floating_ip             = false
  disable_outbound_snat          = false
}
