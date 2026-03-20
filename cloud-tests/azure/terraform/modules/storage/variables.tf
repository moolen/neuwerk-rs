variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "storage_account_name" {
  type = string
}

variable "container_name" {
  type = string
}

variable "neuwerk_binary_path" {
  type = string
}

variable "neuwerk_blob_name" {
  type = string
}

variable "tags" {
  type = map(string)
}
