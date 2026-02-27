output "backend_pool_id" {
  value = azurerm_lb_backend_address_pool.dataplane.id
}

output "private_ip" {
  value = azurerm_lb.dataplane.frontend_ip_configuration[0].private_ip_address
}
