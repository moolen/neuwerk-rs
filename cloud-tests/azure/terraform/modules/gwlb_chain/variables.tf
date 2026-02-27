variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "gwlb_subnet_id" {
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

variable "health_probe_port" {
  type = number
}

variable "tags" {
  type = map(string)
}
