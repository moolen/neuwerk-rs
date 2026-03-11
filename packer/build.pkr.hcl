build {
  name = "ubuntu-2404-amd64"
  sources = [
    "source.qemu.ubuntu_2404_amd64",
    "source.amazon-ebs.ubuntu_2404_amd64",
    "source.azure-arm.ubuntu_2404_amd64",
    "source.googlecompute.ubuntu_2404_amd64"
  ]

  provisioner "file" {
    source      = local.bundle_output_path
    destination = "/tmp/neuwerk-source.tar.gz"
  }

  provisioner "shell" {
    inline = [
      "sudo mkdir -p ${local.guest_repo_dir}",
      "sudo tar -xzf /tmp/neuwerk-source.tar.gz -C ${local.guest_repo_dir} --strip-components=1",
      "sudo chown -R ${var.qemu_ssh_username}:${var.qemu_ssh_username} ${local.guest_repo_dir}"
    ]
  }

  provisioner "shell" {
    environment_vars = [
      "NEUWERK_REPO_DIR=${local.guest_repo_dir}",
      "NEUWERK_TARGET=${var.target}",
      "NEUWERK_RELEASE_ARTIFACT_DIR=${local.guest_release_artifact_dir}"
    ]
    script = "${path.root}/scripts/install-build-deps.sh"
  }

  provisioner "shell" {
    environment_vars = [
      "NEUWERK_REPO_DIR=${local.guest_repo_dir}",
      "NEUWERK_TARGET=${var.target}"
    ]
    script = "${path.root}/scripts/build-dpdk.sh"
  }

  provisioner "shell" {
    environment_vars = [
      "NEUWERK_REPO_DIR=${local.guest_repo_dir}",
      "NEUWERK_TARGET=${var.target}"
    ]
    script = "${path.root}/scripts/build-firewall.sh"
  }

  provisioner "shell" {
    environment_vars = [
      "NEUWERK_REPO_DIR=${local.guest_repo_dir}",
      "NEUWERK_TARGET=${var.target}",
      "NEUWERK_RELEASE_ARTIFACT_DIR=${local.guest_release_artifact_dir}"
    ]
    script = "${path.root}/scripts/stage-runtime.sh"
  }

  provisioner "shell" {
    environment_vars = [
      "NEUWERK_REPO_DIR=${local.guest_repo_dir}",
      "NEUWERK_TARGET=${var.target}",
      "NEUWERK_RELEASE_ARTIFACT_DIR=${local.guest_release_artifact_dir}"
    ]
    script = "${path.root}/scripts/verify-linkage.sh"
  }

  provisioner "shell" {
    environment_vars = [
      "NEUWERK_REPO_DIR=${local.guest_repo_dir}",
      "NEUWERK_TARGET=${var.target}",
      "NEUWERK_RELEASE_ARTIFACT_DIR=${local.guest_release_artifact_dir}"
    ]
    script = "${path.root}/scripts/apply-hardening.sh"
  }

  provisioner "shell" {
    environment_vars = [
      "NEUWERK_REPO_DIR=${local.guest_repo_dir}",
      "NEUWERK_TARGET=${var.target}",
      "NEUWERK_RELEASE_ARTIFACT_DIR=${local.guest_release_artifact_dir}"
    ]
    script = "${path.root}/scripts/cleanup-image.sh"
  }

  provisioner "shell" {
    environment_vars = [
      "NEUWERK_REPO_DIR=${local.guest_repo_dir}",
      "NEUWERK_TARGET=${var.target}",
      "NEUWERK_RELEASE_ARTIFACT_DIR=${local.guest_release_artifact_dir}"
    ]
    script = "${path.root}/scripts/generate-image-sbom.sh"
  }

  provisioner "file" {
    direction   = "download"
    source      = "${local.guest_release_artifact_dir}/"
    destination = "${var.artifact_dir}/release/"
  }

  post-processor "manifest" {
    output     = "${var.artifact_dir}/packer-manifest.json"
    strip_path = true
  }
}
