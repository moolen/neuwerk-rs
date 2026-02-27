variable "subscription_id" {
  type        = string
  default     = ""
  description = "Azure subscription ID (optional; uses Azure CLI context if empty)."
}

variable "location" {
  type        = string
  default     = "Germany West Central"
  description = "Azure region."
}

variable "resource_group_name" {
  type        = string
  default     = "neuwerk-azure-e2e"
  description = "Resource group name."
}

variable "name_prefix" {
  type        = string
  default     = "neuwerk-e2e"
  description = "Prefix for resource names."
}

variable "admin_username" {
  type        = string
  default     = "ubuntu"
  description = "Admin username for VMs."
}

variable "ssh_public_key_path" {
  type        = string
  default     = "../../.secrets/ssh/azure_e2e.pub"
  description = "Path to SSH public key used by all VMs."
}

variable "firewall_binary_path" {
  type        = string
  default     = "./assets/firewall"
  description = "Path to the firewall binary to upload to blob storage."
}

variable "firewall_blob_name" {
  type        = string
  default     = "firewall"
  description = "Blob name for the firewall binary."
}

variable "vnet_cidr" {
  type        = string
  default     = "10.20.0.0/16"
  description = "VNet address space."
}

variable "mgmt_subnet_cidr" {
  type    = string
  default = "10.20.1.0/24"
}

variable "dataplane_subnet_cidr" {
  type    = string
  default = "10.20.2.0/24"
}

variable "consumer_subnet_cidr" {
  type    = string
  default = "10.20.3.0/24"
}

variable "upstream_subnet_cidr" {
  type    = string
  default = "10.20.4.0/24"
}


variable "jumpbox_subnet_cidr" {
  type    = string
  default = "10.20.5.0/24"
}

variable "admin_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR allowed to SSH to the jumpbox."
}

variable "firewall_vmss_size" {
  type    = string
  default = "Standard_D2as_v5"
}

variable "firewall_snat_mode" {
  type        = string
  default     = "none"
  description = "SNAT mode for firewall dataplane (none|auto|<ipv4>). Use none for internal UDR tests, auto when egressing to public networks."
}

variable "firewall_dpdk_workers" {
  type        = number
  default     = 0
  description = "Override DPDK worker count (0 = auto via nproc)."
}

variable "upstream_vm_size" {
  type    = string
  default = "Standard_D2as_v5"
}

variable "consumer_vm_size" {
  type    = string
  default = "Standard_D2as_v5"
}

variable "consumer_attach_gwlb" {
  type        = bool
  default     = false
  description = "Attach consumer NICs directly to the GWLB frontend (use false when relying on the chained upstream LB)."
}

variable "consumer_public_ip_enabled" {
  type        = bool
  default     = false
  description = "Assign public IPs to consumer VMs. Keep false to avoid SNAT and rely on the jumpbox for SSH."
}

variable "jumpbox_vm_size" {
  type    = string
  default = "Standard_B2s"
}

variable "cloud_provider" {
  type        = string
  default     = "azure"
  description = "Cloud provider identifier for dataplane selection (azure|aws|gcp|none)."
}

variable "mgmt_dns_lb_ip" {
  type        = string
  default     = "10.20.1.10"
  description = "Static IP for the internal DNS LB on the management subnet."
}

variable "image_publisher" {
  type        = string
  default     = "Canonical"
  description = "Marketplace image publisher."
}

variable "image_offer" {
  type        = string
  default     = "ubuntu-24_04-lts"
  description = "Marketplace image offer."
}

variable "image_sku" {
  type        = string
  default     = "server"
  description = "Marketplace image SKU."
}

variable "image_version" {
  type        = string
  default     = "latest"
  description = "Marketplace image version."
}

variable "firewall_instance_count" {
  type    = number
  default = 3
}

variable "consumer_count" {
  type    = number
  default = 1
}

variable "dns_zone_name" {
  type    = string
  default = "upstream.test"
}

variable "gwlb_vni_internal" {
  type    = number
  default = 800
}

variable "gwlb_vni_external" {
  type    = number
  default = 801
}

variable "gwlb_udp_port_internal" {
  type    = number
  default = 10800
}

variable "gwlb_udp_port_external" {
  type    = number
  default = 10801
}

variable "gwlb_health_probe_port" {
  type    = number
  default = 8080
}

variable "dataplane_lb_ip" {
  type        = string
  default     = "10.20.2.10"
  description = "Private IP for the internal dataplane LB frontend."
}

variable "dataplane_lb_probe_port" {
  type        = number
  default     = 8080
  description = "Health probe port for the dataplane LB."
}

variable "upstream_lb_ip" {
  type        = string
  default     = "10.20.4.10"
  description = "Private IP for the internal upstream LB frontend."
}

variable "tags" {
  type = map(string)
  default = {
    "neuwerk.io.env" = "azure-e2e"
  }
}
