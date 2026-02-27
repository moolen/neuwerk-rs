output "gwlb_backend_pool_id" {
  value = azurerm_lb_backend_address_pool.gwlb.id
}

output "gwlb_frontend_id" {
  value = azurerm_lb.gwlb.frontend_ip_configuration[0].id
}

output "upstream_backend_pool_id" {
  value = azurerm_lb_backend_address_pool.upstream.id
}

output "upstream_public_ip" {
  value = azurerm_public_ip.upstream.ip_address
}
