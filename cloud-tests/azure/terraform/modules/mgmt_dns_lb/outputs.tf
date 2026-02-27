output "backend_pool_id" {
  value = azurerm_lb_backend_address_pool.dns.id
}

output "private_ip" {
  value = azurerm_lb.dns.frontend_ip_configuration[0].private_ip_address
}
