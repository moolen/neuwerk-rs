variable "region" {
  type        = string
  default     = "eu-central-1"
  description = "AWS region for the e2e bench."
}

variable "availability_zone" {
  type        = string
  default     = "eu-central-1a"
  description = "Single AZ used in phase 1."
}

variable "name_prefix" {
  type        = string
  default     = "neuwerk-aws-e2e"
  description = "Prefix for AWS resources."
}

variable "ssh_public_key_path" {
  type        = string
  default     = "../../.secrets/ssh/aws_e2e.pub"
  description = "Path to SSH public key used by all instances."
}

variable "admin_username" {
  type        = string
  default     = "ubuntu"
  description = "SSH username."
}

variable "admin_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = "CIDR allowed to SSH into jumpbox."
}

variable "vpc_cidr" {
  type        = string
  default     = "10.40.0.0/16"
  description = "Main VPC CIDR."
}

variable "mgmt_subnet_cidr" {
  type    = string
  default = "10.40.1.0/24"
}

variable "dataplane_subnet_cidr" {
  type    = string
  default = "10.40.2.0/24"
}

variable "consumer_subnet_cidr" {
  type    = string
  default = "10.40.3.0/24"
}

variable "upstream_subnet_cidr" {
  type    = string
  default = "10.40.4.0/24"
}

variable "jumpbox_subnet_cidr" {
  type    = string
  default = "10.40.5.0/24"
}

variable "traffic_architecture" {
  type        = string
  default     = "gwlb"
  description = "Traffic steering architecture: gwlb (GWLB+GENEVE) or eni_no_encap (direct routing to firewall ENI)."

  validation {
    condition     = contains(["gwlb", "eni_no_encap"], var.traffic_architecture)
    error_message = "traffic_architecture must be one of: gwlb, eni_no_encap."
  }
}

variable "gwlbe_consumer_subnet_cidr" {
  type    = string
  default = "10.40.6.0/28"
}

variable "gwlbe_upstream_subnet_cidr" {
  type    = string
  default = "10.40.6.16/28"
}

variable "firewall_binary_path" {
  type        = string
  default     = "../../../target/release/firewall"
  description = "Path to the firewall binary uploaded to S3."
}

variable "firewall_object_key" {
  type        = string
  default     = "firewall"
  description = "S3 object key for firewall binary."
}

variable "firewall_dpdk_runtime_bundle_path" {
  type        = string
  default     = ""
  description = "Optional tar.gz path for runtime DPDK libs/PMDs."
}

variable "firewall_dpdk_runtime_object_key" {
  type        = string
  default     = "dpdk-runtime.tar.gz"
  description = "S3 object key for optional DPDK runtime bundle."
}

variable "firewall_instance_type" {
  type        = string
  default     = "c6in.large"
  description = "Firewall instance type (Intel, 2 vCPU target)."
}

variable "firewall_asg_min_size" {
  type        = number
  default     = 1
  description = "Minimum ASG size for firewall nodes (GWLB architecture)."
}

variable "firewall_asg_desired_capacity" {
  type        = number
  default     = 2
  description = "Desired ASG size for firewall nodes (GWLB architecture)."
}

variable "firewall_asg_max_size" {
  type        = number
  default     = 3
  description = "Maximum ASG size for firewall nodes (GWLB architecture)."
}

variable "firewall_asg_heartbeat_timeout_secs" {
  type        = number
  default     = 900
  description = "AWS ASG terminating lifecycle hook heartbeat timeout."
}

variable "consumer_instance_type" {
  type        = string
  default     = "c6in.large"
  description = "Consumer instance type (parity with firewall)."
}

variable "upstream_instance_type" {
  type        = string
  default     = "c6in.large"
  description = "Upstream instance type (parity with firewall)."
}

variable "jumpbox_instance_type" {
  type        = string
  default     = "t3.small"
  description = "Jumpbox instance type."
}

variable "consumer_count" {
  type        = number
  default     = 1
  description = "Number of consumer instances."
}

variable "dns_zone_name" {
  type        = string
  default     = "upstream.test"
  description = "DNS zone served by upstream test VM."
}

variable "dns_target_ips" {
  type        = list(string)
  default     = []
  description = "Repeated --dns-target-ip values. Empty defaults to management IP."
}

variable "dns_upstreams" {
  type        = list(string)
  default     = []
  description = "Repeated --dns-upstream values. Empty defaults to upstream private IP:53."
}

variable "firewall_snat_mode" {
  type        = string
  default     = "none"
  description = "SNAT mode for firewall dataplane."
}

variable "firewall_dpdk_workers" {
  type        = number
  default     = 0
  description = "Override DPDK worker count (0 = auto)."
}

variable "firewall_encap_mtu" {
  type        = number
  default     = 1800
  description = "Firewall overlay encap MTU used for MSS clamping."
}

variable "firewall_dpdk_mbuf_data_room" {
  type        = number
  default     = 4096
  description = "DPDK mbuf data room size in bytes (must cover encapsulated frame size)."
}

variable "firewall_dpdk_port_mtu" {
  type        = number
  default     = 1800
  description = "DPDK port MTU override for GWLB/GENEVE architecture (set to 0 to disable)."
}

variable "firewall_dpdk_port_mtu_no_encap" {
  type        = number
  default     = 1800
  description = "DPDK port MTU override for eni_no_encap architecture (set to 0 to disable)."
}

variable "firewall_dpdk_queue_override" {
  type        = number
  default     = 0
  description = "Optional DPDK queue capability override for probe anomalies (0 disables override)."
}

variable "firewall_dpdk_state_shards" {
  type        = number
  default     = 32
  description = "Optional DPDK state shard count override (0 lets runtime default to worker count)."
}

variable "firewall_dpdk_overlay_debug" {
  type        = bool
  default     = false
  description = "Enable verbose overlay debug logging in dataplane hot path."
}

variable "upstream_private_ip" {
  type        = string
  default     = "10.40.4.20"
  description = "Static private IP assigned to upstream VM."
}

variable "tags" {
  type = map(string)
  default = {
    "neuwerk-io-env"      = "aws-e2e"
    "neuwerk-io-cluster"  = "neuwerk"
    "neuwerk-io-role"     = "dataplane"
    "neuwerk.io.cluster"  = "neuwerk"
    "neuwerk.io.role"     = "dataplane"
    "neuwerk.io.provider" = "aws"
  }
}
