resource "azurerm_lb" "gwlb" {
  name                = "${var.name_prefix}-gwlb"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Gateway"
  tags                = var.tags

  frontend_ip_configuration {
    name                          = "gwlb-fe"
    subnet_id                     = var.gwlb_subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_lb_backend_address_pool" "gwlb" {
  name            = "${var.name_prefix}-gwlb-backend"
  loadbalancer_id = azurerm_lb.gwlb.id

  tunnel_interface {
    identifier = var.gwlb_vni_internal
    type       = "Internal"
    protocol   = "VXLAN"
    port       = var.gwlb_udp_port_internal
  }

  tunnel_interface {
    identifier = var.gwlb_vni_external
    type       = "External"
    protocol   = "VXLAN"
    port       = var.gwlb_udp_port_external
  }
}

resource "azurerm_lb_probe" "gwlb" {
  name                = "${var.name_prefix}-gwlb-probe"
  loadbalancer_id     = azurerm_lb.gwlb.id
  protocol            = "Tcp"
  port                = var.health_probe_port
  interval_in_seconds = 5
  number_of_probes    = 2
}

resource "azurerm_lb_rule" "gwlb" {
  name                           = "${var.name_prefix}-gwlb-rule"
  loadbalancer_id                = azurerm_lb.gwlb.id
  protocol                       = "All"
  frontend_port                  = 0
  backend_port                   = 0
  frontend_ip_configuration_name = azurerm_lb.gwlb.frontend_ip_configuration[0].name
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.gwlb.id]
  probe_id                       = azurerm_lb_probe.gwlb.id
  disable_outbound_snat          = true
}

locals {
  upstream_rules = {
    "tcp-80"   = { protocol = "Tcp", port = 80 }
    "tcp-443"  = { protocol = "Tcp", port = 443 }
    "tcp-9000" = { protocol = "Tcp", port = 9000 }
    "tcp-5201" = { protocol = "Tcp", port = 5201 }
    "tcp-53"   = { protocol = "Tcp", port = 53 }
    "udp-53"   = { protocol = "Udp", port = 53 }
  }
}

resource "azurerm_public_ip" "upstream" {
  name                = "${var.name_prefix}-upstream-ip"
  resource_group_name = var.resource_group_name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_lb" "upstream" {
  name                = "${var.name_prefix}-upstream-lb"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Standard"
  tags                = var.tags

  frontend_ip_configuration {
    name                                               = "upstream-fe"
    public_ip_address_id                               = azurerm_public_ip.upstream.id
    gateway_load_balancer_frontend_ip_configuration_id = azurerm_lb.gwlb.frontend_ip_configuration[0].id
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
  disable_outbound_snat          = false
}
