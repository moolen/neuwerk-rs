output "vnet_id" {
  value = azurerm_virtual_network.main.id
}

output "mgmt_subnet_id" {
  value = azurerm_subnet.mgmt.id
}

output "dataplane_subnet_id" {
  value = azurerm_subnet.dataplane.id
}

output "consumer_subnet_id" {
  value = azurerm_subnet.consumer.id
}

output "upstream_subnet_id" {
  value = azurerm_subnet.upstream.id
}

output "jumpbox_subnet_id" {
  value = azurerm_subnet.jumpbox.id
}
