source "qemu" "ubuntu_2404_amd64" {
  accelerator      = var.qemu_accelerator
  boot_wait        = "5s"
  communicator     = "ssh"
  cpus             = var.qemu_cpus
  disk_image       = true
  disk_size        = var.qemu_disk_size
  format           = "qcow2"
  headless         = true
  iso_checksum     = var.qemu_source_image_checksum
  iso_url          = var.qemu_source_image_url
  memory           = var.qemu_memory
  output_directory = local.qemu_output_dir
  shutdown_command = "echo '${var.qemu_ssh_password}' | sudo -S systemctl poweroff"
  ssh_password     = var.qemu_ssh_password
  ssh_timeout      = "30m"
  ssh_username     = var.qemu_ssh_username
  vm_name          = "neuwerk-${var.target}.qcow2"

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
