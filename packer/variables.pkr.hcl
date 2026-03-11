variable "target" {
  type    = string
  default = "ubuntu-24.04-amd64"
}

variable "release_version" {
  type    = string
  default = "dev"
}

variable "git_revision" {
  type    = string
  default = "dirty"
}

variable "artifact_dir" {
  type    = string
  default = "artifacts/image-build"
}

variable "qemu_source_image_url" {
  type    = string
  default = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
}

variable "qemu_source_image_checksum" {
  type    = string
  default = "none"
}

variable "qemu_accelerator" {
  type    = string
  default = "kvm"
}

variable "use_prebuilt_artifacts" {
  type    = bool
  default = false
}

variable "qemu_cpus" {
  type    = number
  default = 4
}

variable "qemu_memory" {
  type    = number
  default = 8192
}

variable "qemu_disk_size" {
  type    = string
  default = "40G"
}

variable "qemu_ssh_username" {
  type    = string
  default = "ubuntu"
}

variable "qemu_ssh_password" {
  type    = string
  default = "neuwerk"
}

variable "qemu_ssh_public_key" {
  type    = string
  default = ""
}

variable "qemu_ssh_private_key_file" {
  type    = string
  default = ""
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "aws_instance_type" {
  type    = string
  default = "c6in.large"
}

variable "aws_ami_name_prefix" {
  type    = string
  default = "neuwerk"
}

variable "azure_subscription_id" {
  type    = string
  default = ""
}

variable "azure_tenant_id" {
  type    = string
  default = ""
}

variable "azure_client_id" {
  type    = string
  default = ""
}

variable "azure_client_secret" {
  type    = string
  default = ""
}

variable "azure_location" {
  type    = string
  default = "Germany West Central"
}

variable "azure_build_resource_group_name" {
  type    = string
  default = "neuwerk-packer-build"
}

variable "azure_managed_image_resource_group_name" {
  type    = string
  default = "neuwerk-images"
}

variable "azure_managed_image_name_prefix" {
  type    = string
  default = "neuwerk"
}

variable "azure_vm_size" {
  type    = string
  default = "Standard_D4s_v5"
}

variable "gcp_project_id" {
  type    = string
  default = ""
}

variable "gcp_zone" {
  type    = string
  default = "europe-west3-a"
}

variable "gcp_source_image_project" {
  type    = string
  default = "ubuntu-os-cloud"
}

variable "gcp_source_image_family" {
  type    = string
  default = "ubuntu-2404-lts-amd64"
}

variable "gcp_machine_type" {
  type    = string
  default = "n2-standard-4"
}

variable "gcp_image_name_prefix" {
  type    = string
  default = "neuwerk"
}
