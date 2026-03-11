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
    Name                    = "${var.aws_ami_name_prefix}-${var.target}"
    "neuwerk.io/target"     = var.target
    "neuwerk.io/revision"   = var.git_revision
    "neuwerk.io/release"    = var.release_version
  }
}
