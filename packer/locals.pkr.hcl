locals {
  repo_root                   = abspath("${path.root}/..")
  guest_repo_dir              = "/tmp/firewall-src"
  guest_release_artifact_dir  = "/tmp/neuwerk-release/${var.target}"
  bundle_output_dir           = "${var.artifact_dir}/source"
  bundle_output_path          = "${local.bundle_output_dir}/${var.target}.tar.gz"
  prebuilt_bundle_output_path = "${local.bundle_output_dir}/${var.target}-prebuilt.tar.gz"
  qemu_output_dir             = "${var.artifact_dir}/qemu/${var.target}"
  release_artifact_dir        = "${var.artifact_dir}/release/${var.target}"
}
