variable "project_id" {
  type        = string
  default     = "external-secrets-361720"
  description = "GCP project ID."
}

variable "region" {
  type        = string
  default     = "europe-west3"
  description = "GCP region (Frankfurt)."
}

variable "zone" {
  type        = string
  default     = "europe-west3-a"
  description = "GCP zone used by the test bench."
}

variable "name_prefix" {
  type        = string
  default     = "neuwerk-gcp-e2e"
  description = "Prefix for resource names."
}

variable "admin_username" {
  type        = string
  default     = "ubuntu"
  description = "Admin username for VM SSH keys."
}

variable "ssh_public_key_path" {
  type        = string
  default     = "../../.secrets/ssh/gcp_e2e.pub"
  description = "Path to the SSH public key used by all VMs."
}

variable "admin_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR allowed to SSH into the jumpbox."
}

variable "firewall_binary_path" {
  type        = string
  default     = "../../../target/release/firewall"
  description = "Path to the firewall binary uploaded to GCS."
}

variable "firewall_blob_name" {
  type        = string
  default     = "firewall"
  description = "Object name for the uploaded firewall binary."
}

variable "firewall_dpdk_runtime_bundle_path" {
  type        = string
  default     = "../assets/dpdk-runtime-26.tar.gz"
  description = "Path to tar.gz containing DPDK runtime libs/PMDs required by the firewall binary."
}

variable "firewall_dpdk_runtime_blob_name" {
  type        = string
  default     = "dpdk-runtime-26.tar.gz"
  description = "Object name for uploaded DPDK runtime bundle."
}

variable "vpc_cidr" {
  type    = string
  default = "10.30.0.0/16"
}

variable "mgmt_subnet_cidr" {
  type    = string
  default = "10.30.1.0/24"
}

variable "dataplane_subnet_cidr" {
  type    = string
  default = "10.30.2.0/24"
}

variable "consumer_subnet_cidr" {
  type    = string
  default = "10.30.3.0/24"
}

variable "upstream_subnet_cidr" {
  type    = string
  default = "10.30.4.0/24"
}

variable "jumpbox_subnet_cidr" {
  type    = string
  default = "10.30.5.0/24"
}

variable "firewall_machine_type" {
  type    = string
  default = "n2-standard-4"
}

variable "upstream_machine_type" {
  type    = string
  default = "e2-standard-2"
}

variable "consumer_machine_type" {
  type    = string
  default = "e2-standard-2"
}

variable "jumpbox_machine_type" {
  type    = string
  default = "e2-small"
}

variable "firewall_instance_count" {
  type    = number
  default = 1
}

variable "consumer_count" {
  type    = number
  default = 1
}

variable "boot_disk_size_gb" {
  type    = number
  default = 40
}

variable "image_project" {
  type    = string
  default = "ubuntu-os-cloud"
}

variable "image_family" {
  type    = string
  default = "ubuntu-2404-lts-amd64"
}

variable "dns_zone_name" {
  type    = string
  default = "upstream.test"
}

variable "dns_target_ips" {
  type        = list(string)
  default     = []
  description = "DNS target IPs for repeated --dns-target-ip flags. Empty defaults to management IP."
}

variable "dns_upstreams" {
  type        = list(string)
  default     = []
  description = "DNS upstream resolvers for repeated --dns-upstream flags. Empty defaults to upstream VM :53."
}

variable "firewall_snat_mode" {
  type        = string
  default     = "none"
  description = "SNAT mode for firewall dataplane (none|auto|<ipv4>)."
}

variable "firewall_dpdk_workers" {
  type        = number
  default     = 0
  description = "Override DPDK worker count (0 = auto via nproc)."
}

variable "firewall_total_nic_queue_count" {
  type        = number
  default     = 8
  description = "Total gVNIC queue budget on firewall VMs; dataplane uses total minus management queues."
}

variable "firewall_mgmt_queue_count" {
  type        = number
  default     = 1
  description = "Queue count reserved for the management NIC on firewall VMs."
}

variable "cloud_provider" {
  type        = string
  default     = "gcp"
  description = "Cloud provider identifier passed to the firewall process."
}

variable "dataplane_lb_ip" {
  type        = string
  default     = "10.30.2.10"
  description = "Internal dataplane ILB VIP on dataplane subnet (debug/optional)."
}

variable "consumer_dataplane_lb_ip" {
  type        = string
  default     = "10.30.3.10"
  description = "Internal dataplane ILB VIP used as next-hop from consumers."
}

variable "upstream_dataplane_lb_ip" {
  type        = string
  default     = "10.30.4.11"
  description = "Internal dataplane ILB VIP used as next-hop from upstream."
}

variable "upstream_lb_ip" {
  type        = string
  default     = "10.30.4.10"
  description = "Internal upstream ILB VIP."
}

variable "upstream_vm_ip" {
  type        = string
  default     = "10.30.4.20"
  description = "Internal IP assigned to the upstream VM backend."
}

variable "tags" {
  type = map(string)
  default = {
    "neuwerk-io-env"     = "gcp-e2e"
    "neuwerk-io-cluster" = "neuwerk"
    "neuwerk-io-role"    = "dataplane"
  }
}
