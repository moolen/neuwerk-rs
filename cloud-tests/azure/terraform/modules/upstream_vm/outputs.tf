output "private_ip" {
  value = try(azurerm_network_interface.upstream[0].private_ip_address, null)
}

output "private_ips" {
  value = azurerm_network_interface.upstream[*].private_ip_address
}
