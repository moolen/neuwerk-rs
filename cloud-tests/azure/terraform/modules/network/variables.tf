variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "vnet_cidr" {
  type = string
}

variable "mgmt_subnet_cidr" {
  type = string
}

variable "dataplane_subnet_cidr" {
  type = string
}

variable "consumer_subnet_cidr" {
  type = string
}

variable "upstream_subnet_cidr" {
  type = string
}

variable "jumpbox_subnet_cidr" {
  type = string
}

variable "admin_cidr" {
  type = string
}

variable "tags" {
  type = map(string)
}
