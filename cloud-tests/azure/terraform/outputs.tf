output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "jumpbox_public_ip" {
  value = module.jumpbox.public_ip
}

output "mgmt_subnet_id" {
  value = module.network.mgmt_subnet_id
}

output "mgmt_subnet_cidr" {
  value = var.mgmt_subnet_cidr
}

output "dataplane_subnet_id" {
  value = module.network.dataplane_subnet_id
}

output "upstream_private_ip" {
  value = module.upstream_vm.private_ip
}

output "upstream_private_ips" {
  value = module.upstream_vm.private_ips
}

output "consumer_private_ips" {
  value = module.consumer_vms.private_ips
}

output "consumer_all_private_ips" {
  value = module.consumer_vms.all_private_ips
}

output "consumer_public_ips" {
  value = module.consumer_vms.public_ips
}

output "upstream_vip" {
  value = module.upstream_lb.private_ip
}

output "dataplane_lb_ip" {
  value = module.dataplane_lb.private_ip
}

output "gwlb_tunnel" {
  value = {
    vni_internal      = var.gwlb_vni_internal
    vni_external      = var.gwlb_vni_external
    udp_port_internal = var.gwlb_udp_port_internal
    udp_port_external = var.gwlb_udp_port_external
  }
}

output "neuwerk_vmss" {
  value = {
    name           = module.neuwerk_vmss.name
    resource_group = azurerm_resource_group.main.name
  }
}
