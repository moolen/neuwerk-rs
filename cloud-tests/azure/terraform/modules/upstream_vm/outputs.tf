output "private_ip" {
  value = azurerm_network_interface.upstream.private_ip_address
}
