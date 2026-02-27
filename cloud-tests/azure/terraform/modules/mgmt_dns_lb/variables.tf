variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "mgmt_subnet_id" {
  type = string
}

variable "mgmt_dns_lb_ip" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
