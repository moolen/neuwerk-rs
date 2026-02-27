variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "vm_size" {
  type = string
}

variable "instance_count" {
  type = number
}

variable "admin_username" {
  type = string
}

variable "ssh_public_key" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "gwlb_frontend_id" {
  type = string
}

variable "attach_gwlb" {
  type    = bool
  default = false
}

variable "public_ip_enabled" {
  type    = bool
  default = false
}

variable "tags" {
  type = map(string)
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
