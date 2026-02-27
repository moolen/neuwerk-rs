output "private_ips" {
  value = azurerm_network_interface.consumer[*].private_ip_address
}

output "public_ips" {
  value = var.public_ip_enabled ? azurerm_public_ip.consumer[*].ip_address : []
}
