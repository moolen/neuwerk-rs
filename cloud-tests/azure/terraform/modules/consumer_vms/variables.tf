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

variable "secondary_private_ip_count" {
  type    = number
  default = 0

  validation {
    condition     = var.secondary_private_ip_count >= 0 && floor(var.secondary_private_ip_count) == var.secondary_private_ip_count
    error_message = "secondary_private_ip_count must be a non-negative integer."
  }
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
