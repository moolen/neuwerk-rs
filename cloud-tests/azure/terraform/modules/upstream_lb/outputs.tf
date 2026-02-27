output "backend_pool_id" {
  value = azurerm_lb_backend_address_pool.upstream.id
}

output "private_ip" {
  value = azurerm_lb.upstream.frontend_ip_configuration[0].private_ip_address
}
