variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "private_ip" {
  type = string
}

variable "health_probe_port" {
  type    = number
  default = 8080
}

variable "tags" {
  type = map(string)
}
