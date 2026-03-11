variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "instance_count" {
  type = number
}

variable "vm_size" {
  type = string
}

variable "admin_username" {
  type = string
}

variable "ssh_public_key" {
  type = string
}

variable "mgmt_subnet_id" {
  type = string
}

variable "dataplane_subnet_id" {
  type = string
}

variable "dataplane_lb_backend_pool_id" {
  type = string
}

variable "dns_target_ips" {
  type = list(string)
}

variable "dns_upstreams" {
  type = list(string)
}

variable "dns_zone_name" {
  type = string
}

variable "gwlb_vni_internal" {
  type = number
}

variable "gwlb_vni_external" {
  type = number
}

variable "gwlb_udp_port_internal" {
  type = number
}

variable "gwlb_udp_port_external" {
  type = number
}

variable "internal_cidr" {
  type = string
}

variable "snat_mode" {
  type = string
}

variable "dpdk_workers" {
  type = number
}

variable "storage_account_name" {
  type = string
}

variable "storage_container_name" {
  type = string
}

variable "storage_blob_name" {
  type = string
}

variable "azure_subscription_id" {
  type = string
}

variable "azure_resource_group" {
  type = string
}

variable "azure_vmss_name" {
  type = string
}

variable "cloud_provider" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "firewall_image_id" {
  type = string
}

variable "image_publisher" {
  type = string
}

variable "image_offer" {
  type = string
}

variable "image_sku" {
  type = string
}

variable "image_version" {
  type = string
}
