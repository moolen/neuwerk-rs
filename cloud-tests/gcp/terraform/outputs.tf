output "project_id" {
  value = var.project_id
}

output "region" {
  value = var.region
}

output "zone" {
  value = var.zone
}

output "network" {
  value = google_compute_network.main.name
}

output "jumpbox_public_ip" {
  value = google_compute_instance.jumpbox.network_interface[0].access_config[0].nat_ip
}

output "mgmt_subnet_name" {
  value = google_compute_subnetwork.mgmt.name
}

output "mgmt_subnet_cidr" {
  value = var.mgmt_subnet_cidr
}

output "upstream_private_ip" {
  value = google_compute_instance.upstream.network_interface[0].network_ip
}

output "consumer_private_ips" {
  value = [for vm in google_compute_instance.consumer : vm.network_interface[0].network_ip]
}

output "upstream_vip" {
  value = google_compute_address.upstream_ilb.address
}

output "dataplane_lb_ip" {
  value = google_compute_address.dataplane_ilb.address
}

output "consumer_dataplane_lb_ip" {
  value = google_compute_address.dataplane_consumer_ilb.address
}

output "upstream_dataplane_lb_ip" {
  value = google_compute_address.dataplane_upstream_ilb.address
}

output "neuwerk_igm" {
  value = {
    name = google_compute_instance_group_manager.neuwerk.name
    zone = google_compute_instance_group_manager.neuwerk.zone
  }
}

output "instance_sizes" {
  value = {
    neuwerk  = var.neuwerk_machine_type
    upstream = var.upstream_machine_type
    consumer = var.consumer_machine_type
    jumpbox  = var.jumpbox_machine_type
  }
}
