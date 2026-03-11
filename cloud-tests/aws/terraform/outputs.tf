output "region" {
  value = var.region
}

output "availability_zone" {
  value = var.availability_zone
}

output "traffic_architecture" {
  value = var.traffic_architecture
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "jumpbox_public_ip" {
  value = aws_instance.jumpbox.public_ip
}

output "mgmt_subnet_id" {
  value = aws_subnet.mgmt.id
}

output "mgmt_subnet_cidr" {
  value = var.mgmt_subnet_cidr
}

output "dataplane_subnet_id" {
  value = aws_subnet.dataplane.id
}

output "upstream_private_ip" {
  value = aws_instance.upstream.private_ip
}

output "consumer_private_ips" {
  value = [for vm in aws_instance.consumer : vm.private_ip]
}

output "upstream_vip" {
  value = aws_instance.upstream.private_ip
}

output "firewall_instance" {
  value = local.use_gwlb ? null : {
    private_ip_mgmt   = aws_network_interface.firewall_mgmt[0].private_ip
    private_ip_data   = aws_network_interface.firewall_data[0].private_ip
    availability_zone = var.availability_zone
  }
}

output "firewall_mgmt_ips" {
  value = local.use_gwlb ? [] : [aws_network_interface.firewall_mgmt[0].private_ip]
}

output "firewall_asg_name" {
  value = local.use_gwlb ? aws_autoscaling_group.firewall[0].name : null
}

output "gwlb" {
  value = local.use_gwlb ? {
    arn                   = aws_lb.firewall[0].arn
    dns_name              = aws_lb.firewall[0].dns_name
    endpoint_service_name = aws_vpc_endpoint_service.gwlb[0].service_name
    endpoint_consumer_id  = aws_vpc_endpoint.consumer[0].id
    endpoint_upstream_id  = aws_vpc_endpoint.upstream[0].id
  } : null
}

output "instance_sizes" {
  value = {
    firewall = var.firewall_instance_type
    upstream = var.upstream_instance_type
    consumer = var.consumer_instance_type
    jumpbox  = var.jumpbox_instance_type
  }
}

output "ssh_key_name" {
  value = aws_key_pair.main.key_name
}
