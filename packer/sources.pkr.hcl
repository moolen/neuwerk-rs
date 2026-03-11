source "qemu" "ubuntu_2404_amd64" {
  accelerator          = var.qemu_accelerator
  boot_wait            = "5s"
  communicator         = "ssh"
  cpus                 = var.qemu_cpus
  disk_image           = true
  disk_size            = var.qemu_disk_size
  format               = "qcow2"
  headless             = true
  iso_checksum         = var.qemu_source_image_checksum
  iso_url              = var.qemu_source_image_url
  memory               = var.qemu_memory
  output_directory     = local.qemu_output_dir
  shutdown_command     = "echo '${var.qemu_ssh_password}' | sudo -S systemctl poweroff"
  ssh_password         = var.qemu_ssh_password
  ssh_private_key_file = var.qemu_ssh_private_key_file != "" ? var.qemu_ssh_private_key_file : null
  ssh_timeout          = "30m"
  ssh_username         = var.qemu_ssh_username
  vm_name              = "neuwerk-${var.target}.qcow2"

  cd_label = "cidata"
  cd_content = {
    "meta-data" = "instance-id: neuwerk-qemu\nlocal-hostname: neuwerk-qemu\n"
    "user-data" = templatefile("${path.root}/http/qemu-user-data.pkrtpl.hcl", {
      ssh_username   = var.qemu_ssh_username
      ssh_password   = var.qemu_ssh_password
      ssh_public_key = var.qemu_ssh_public_key
    })
  }
}

source "amazon-ebs" "ubuntu_2404_amd64" {
  ami_name      = "${var.aws_ami_name_prefix}-${var.target}-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  instance_type = var.aws_instance_type
  region        = var.aws_region
  ssh_username  = "ubuntu"

  source_ami_filter {
    filters = {
      architecture        = "x86_64"
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }

  tags = {
    Name                  = "${var.aws_ami_name_prefix}-${var.target}"
    "neuwerk.io/target"   = var.target
    "neuwerk.io/revision" = var.git_revision
    "neuwerk.io/release"  = var.release_version
  }
}

source "azure-arm" "ubuntu_2404_amd64" {
  client_id                         = var.azure_client_id
  client_secret                     = var.azure_client_secret
  managed_image_name                = "${var.azure_managed_image_name_prefix}-${var.target}-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  managed_image_resource_group_name = var.azure_managed_image_resource_group_name
  os_type                           = "Linux"
  image_offer                       = "ubuntu-24_04-lts"
  image_publisher                   = "Canonical"
  image_sku                         = "server"
  location                          = var.azure_location
  subscription_id                   = var.azure_subscription_id
  tenant_id                         = var.azure_tenant_id
  temporary_resource_group_name     = var.azure_build_resource_group_name
  vm_size                           = var.azure_vm_size
  azure_tags = {
    "neuwerk.io/target"   = var.target
    "neuwerk.io/revision" = var.git_revision
    "neuwerk.io/release"  = var.release_version
  }
}

source "googlecompute" "ubuntu_2404_amd64" {
  disk_size               = 40
  image_family            = var.target
  image_name              = "${var.gcp_image_name_prefix}-${var.target}-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  machine_type            = var.gcp_machine_type
  project_id              = var.gcp_project_id
  source_image_family     = var.gcp_source_image_family
  source_image_project_id = [var.gcp_source_image_project]
  ssh_username            = "ubuntu"
  zone                    = var.gcp_zone
  labels = {
    neuwerk_target  = replace(var.target, ".", "-")
    neuwerk_release = replace(var.release_version, ".", "-")
  }
}
