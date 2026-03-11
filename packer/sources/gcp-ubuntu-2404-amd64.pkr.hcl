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
