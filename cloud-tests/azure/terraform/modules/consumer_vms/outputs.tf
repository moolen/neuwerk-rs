output "private_ips" {
  value = azurerm_network_interface.consumer[*].private_ip_address
}

output "all_private_ips" {
  value = [for nic in azurerm_network_interface.consumer : [for cfg in nic.ip_configuration : cfg.private_ip_address]]
}

output "public_ips" {
  value = var.public_ip_enabled ? azurerm_public_ip.consumer[*].ip_address : []
}
