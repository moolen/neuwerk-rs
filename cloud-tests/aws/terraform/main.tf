resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

data "aws_caller_identity" "current" {}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

locals {
  name_suffix      = random_string.suffix.result
  name_prefix      = "${var.name_prefix}-${local.name_suffix}"
  bucket_name      = substr(replace(lower("${var.name_prefix}-${data.aws_caller_identity.current.account_id}-${local.name_suffix}"), "_", "-"), 0, 63)
  runtime_enabled  = trimspace(var.neuwerk_dpdk_runtime_bundle_path) != ""
  use_gwlb         = var.traffic_architecture == "gwlb"
  neuwerk_encap    = local.use_gwlb ? "geneve" : "none"
  dpdk_port_mtu    = local.use_gwlb ? var.neuwerk_dpdk_port_mtu : var.neuwerk_dpdk_port_mtu_no_encap
  endpoint_mtu     = local.use_gwlb ? var.neuwerk_encap_mtu : local.dpdk_port_mtu
  ssh_public_key   = file(var.ssh_public_key_path)
  dns_target_ips   = length(var.dns_target_ips) > 0 ? var.dns_target_ips : ["$${MGMT_IP}"]
  dns_upstreams    = length(var.dns_upstreams) > 0 ? var.dns_upstreams : ["${aws_instance.upstream.private_ip}:53"]
  neuwerk_tag_set  = merge(var.tags, { "Name" = "${local.name_prefix}-neuwerk-0" })
  neuwerk_asg_name = "${local.name_prefix}-fw-asg"
  neuwerk_ami_id   = trimspace(var.neuwerk_ami_id) != "" ? trimspace(var.neuwerk_ami_id) : data.aws_ami.ubuntu.id
}

resource "aws_key_pair" "main" {
  key_name   = "${local.name_prefix}-ssh"
  public_key = local.ssh_public_key
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(var.tags, { Name = "${local.name_prefix}-vpc" })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.tags, { Name = "${local.name_prefix}-igw" })
}

resource "aws_subnet" "mgmt" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.mgmt_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${local.name_prefix}-mgmt" })
}

resource "aws_subnet" "dataplane" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.dataplane_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${local.name_prefix}-dataplane" })
}

resource "aws_subnet" "consumer" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.consumer_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${local.name_prefix}-consumer" })
}

resource "aws_subnet" "upstream" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.upstream_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${local.name_prefix}-upstream" })
}

resource "aws_subnet" "jumpbox" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.jumpbox_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
  tags                    = merge(var.tags, { Name = "${local.name_prefix}-jumpbox" })
}

resource "aws_subnet" "gwlbe_consumer" {
  count                   = local.use_gwlb ? 1 : 0
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.gwlbe_consumer_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${local.name_prefix}-gwlbe-consumer" })
}

resource "aws_subnet" "gwlbe_upstream" {
  count                   = local.use_gwlb ? 1 : 0
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.gwlbe_upstream_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${local.name_prefix}-gwlbe-upstream" })
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${local.name_prefix}-nat-eip" })
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.jumpbox.id
  tags          = merge(var.tags, { Name = "${local.name_prefix}-nat" })
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = merge(var.tags, { Name = "${local.name_prefix}-rt-public" })
}

resource "aws_route_table_association" "jumpbox" {
  subnet_id      = aws_subnet.jumpbox.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "mgmt" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = merge(var.tags, { Name = "${local.name_prefix}-rt-mgmt" })
}

resource "aws_route_table_association" "mgmt" {
  subnet_id      = aws_subnet.mgmt.id
  route_table_id = aws_route_table.mgmt.id
}

resource "aws_route_table" "dataplane" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = merge(var.tags, { Name = "${local.name_prefix}-rt-dataplane" })
}

resource "aws_route_table_association" "dataplane" {
  subnet_id      = aws_subnet.dataplane.id
  route_table_id = aws_route_table.dataplane.id
}

resource "aws_route_table" "consumer" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  # This table also has separately-managed aws_route entries for test steering.
  # Ignore route drift here to avoid provider churn deleting those entries.
  lifecycle {
    ignore_changes = [route]
  }
  tags = merge(var.tags, { Name = "${local.name_prefix}-rt-consumer" })
}

resource "aws_route_table_association" "consumer" {
  subnet_id      = aws_subnet.consumer.id
  route_table_id = aws_route_table.consumer.id
}

resource "aws_route_table" "upstream" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  # This table also has separately-managed aws_route entries for test steering.
  # Ignore route drift here to avoid provider churn deleting those entries.
  lifecycle {
    ignore_changes = [route]
  }
  tags = merge(var.tags, { Name = "${local.name_prefix}-rt-upstream" })
}

resource "aws_route_table_association" "upstream" {
  subnet_id      = aws_subnet.upstream.id
  route_table_id = aws_route_table.upstream.id
}

resource "aws_route" "consumer_to_upstream_gwlbe" {
  count                  = local.use_gwlb ? 1 : 0
  route_table_id         = aws_route_table.consumer.id
  destination_cidr_block = var.upstream_subnet_cidr
  vpc_endpoint_id        = aws_vpc_endpoint.consumer[0].id
}

resource "aws_route" "consumer_to_upstream_eni" {
  count                  = local.use_gwlb ? 0 : 1
  route_table_id         = aws_route_table.consumer.id
  destination_cidr_block = var.upstream_subnet_cidr
  network_interface_id   = aws_network_interface.neuwerk_data[0].id
}

resource "aws_route" "upstream_to_consumer_gwlbe" {
  count                  = local.use_gwlb ? 1 : 0
  route_table_id         = aws_route_table.upstream.id
  destination_cidr_block = var.consumer_subnet_cidr
  # Keep both flow directions on the same GWLBE for this verification topology.
  vpc_endpoint_id = aws_vpc_endpoint.consumer[0].id
}

resource "aws_route" "upstream_to_consumer_eni" {
  count                  = local.use_gwlb ? 0 : 1
  route_table_id         = aws_route_table.upstream.id
  destination_cidr_block = var.consumer_subnet_cidr
  network_interface_id   = aws_network_interface.neuwerk_data[0].id
}

resource "aws_route_table" "gwlbe_consumer" {
  count  = local.use_gwlb ? 1 : 0
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = merge(var.tags, { Name = "${local.name_prefix}-rt-gwlbe-consumer" })
}

resource "aws_route_table_association" "gwlbe_consumer" {
  count          = local.use_gwlb ? 1 : 0
  subnet_id      = aws_subnet.gwlbe_consumer[0].id
  route_table_id = aws_route_table.gwlbe_consumer[0].id
}

resource "aws_route_table" "gwlbe_upstream" {
  count  = local.use_gwlb ? 1 : 0
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = merge(var.tags, { Name = "${local.name_prefix}-rt-gwlbe-upstream" })
}

resource "aws_route_table_association" "gwlbe_upstream" {
  count          = local.use_gwlb ? 1 : 0
  subnet_id      = aws_subnet.gwlbe_upstream[0].id
  route_table_id = aws_route_table.gwlbe_upstream[0].id
}

resource "aws_security_group" "jumpbox" {
  name        = "${local.name_prefix}-jumpbox"
  description = "Jumpbox access"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${local.name_prefix}-sg-jumpbox" })
}

resource "aws_security_group" "neuwerk_mgmt" {
  name        = "${local.name_prefix}-fw-mgmt"
  description = "Neuwerk management interface"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.jumpbox_subnet_cidr]
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.consumer_subnet_cidr, var.jumpbox_subnet_cidr]
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.consumer_subnet_cidr, var.jumpbox_subnet_cidr]
  }

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.consumer_subnet_cidr, var.jumpbox_subnet_cidr, var.mgmt_subnet_cidr]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.consumer_subnet_cidr, var.jumpbox_subnet_cidr, var.mgmt_subnet_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${local.name_prefix}-sg-fw-mgmt" })
}

resource "aws_security_group" "neuwerk_data" {
  name        = "${local.name_prefix}-fw-data"
  description = "Neuwerk dataplane interface"
  vpc_id      = aws_vpc.main.id

  dynamic "ingress" {
    for_each = local.use_gwlb ? [
      {
        from_port   = 6081
        to_port     = 6081
        protocol    = "udp"
        cidr_blocks = [var.vpc_cidr]
      },
      {
        from_port   = 8080
        to_port     = 8080
        protocol    = "tcp"
        cidr_blocks = [var.vpc_cidr]
      },
      {
        from_port   = 0
        to_port     = 0
        protocol    = "icmp"
        cidr_blocks = [var.vpc_cidr]
      }
      ] : [
      {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [var.consumer_subnet_cidr, var.upstream_subnet_cidr, var.dataplane_subnet_cidr]
      },
      {
        from_port   = 8080
        to_port     = 8080
        protocol    = "tcp"
        cidr_blocks = [var.vpc_cidr]
      }
    ]

    content {
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${local.name_prefix}-sg-fw-data" })
}

resource "aws_security_group" "consumer" {
  name        = "${local.name_prefix}-consumer"
  description = "Consumer VM"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.jumpbox_subnet_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${local.name_prefix}-sg-consumer" })
}

resource "aws_security_group" "upstream" {
  name        = "${local.name_prefix}-upstream"
  description = "Upstream VM"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.jumpbox_subnet_cidr]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.consumer_subnet_cidr]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.consumer_subnet_cidr]
  }

  ingress {
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = [var.consumer_subnet_cidr]
  }

  ingress {
    from_port   = 5201
    to_port     = 5201
    protocol    = "tcp"
    cidr_blocks = [var.consumer_subnet_cidr]
  }

  ingress {
    from_port   = 5201
    to_port     = 5201
    protocol    = "udp"
    cidr_blocks = [var.consumer_subnet_cidr]
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.consumer_subnet_cidr, var.mgmt_subnet_cidr]
  }

  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.consumer_subnet_cidr, var.mgmt_subnet_cidr]
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.consumer_subnet_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${local.name_prefix}-sg-upstream" })
}

resource "aws_s3_bucket" "neuwerk" {
  bucket        = local.bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = "${local.name_prefix}-neuwerk-bin" })
}

resource "aws_s3_bucket_public_access_block" "neuwerk" {
  bucket                  = aws_s3_bucket.neuwerk.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "neuwerk_binary" {
  bucket = aws_s3_bucket.neuwerk.id
  key    = var.neuwerk_object_key
  source = var.neuwerk_binary_path
  etag   = filemd5(var.neuwerk_binary_path)
}

resource "aws_s3_object" "neuwerk_runtime_bundle" {
  count  = local.runtime_enabled ? 1 : 0
  bucket = aws_s3_bucket.neuwerk.id
  key    = var.neuwerk_dpdk_runtime_object_key
  source = var.neuwerk_dpdk_runtime_bundle_path
  etag   = filemd5(var.neuwerk_dpdk_runtime_bundle_path)
}

resource "aws_iam_role" "neuwerk" {
  name = "${local.name_prefix}-fw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "neuwerk_s3_read" {
  name = "${local.name_prefix}-fw-s3-read"
  role = aws_iam_role.neuwerk.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:ListBucket"],
        Resource = [aws_s3_bucket.neuwerk.arn]
      },
      {
        Effect = "Allow",
        Action = ["s3:GetObject"],
        Resource = [
          "${aws_s3_bucket.neuwerk.arn}/${var.neuwerk_object_key}",
          "${aws_s3_bucket.neuwerk.arn}/${var.neuwerk_dpdk_runtime_object_key}"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:ModifyNetworkInterfaceAttribute",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLifecycleHooks",
          "autoscaling:SetInstanceProtection",
          "autoscaling:CompleteLifecycleAction",
          "autoscaling:RecordLifecycleActionHeartbeat",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:DescribeTargetHealth"
        ],
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "neuwerk" {
  name = "${local.name_prefix}-fw-profile"
  role = aws_iam_role.neuwerk.name
}

resource "aws_network_interface" "neuwerk_mgmt" {
  count           = local.use_gwlb ? 0 : 1
  subnet_id       = aws_subnet.mgmt.id
  security_groups = [aws_security_group.neuwerk_mgmt.id]
  tags = merge(var.tags, {
    Name                    = "${local.name_prefix}-fw-mgmt-eni"
    "neuwerk.io/management" = "true"
    "neuwerk.io/dataplane"  = "false"
  })
}

resource "aws_network_interface" "neuwerk_data" {
  count             = local.use_gwlb ? 0 : 1
  subnet_id         = aws_subnet.dataplane.id
  security_groups   = [aws_security_group.neuwerk_data.id]
  source_dest_check = false
  tags = merge(var.tags, {
    Name                    = "${local.name_prefix}-fw-data-eni"
    "neuwerk.io/management" = "false"
    "neuwerk.io/dataplane"  = "true"
  })
}

resource "aws_instance" "neuwerk" {
  count                = local.use_gwlb ? 0 : 1
  ami                  = local.neuwerk_ami_id
  instance_type        = var.neuwerk_instance_type
  key_name             = aws_key_pair.main.key_name
  iam_instance_profile = aws_iam_instance_profile.neuwerk.name

  network_interface {
    network_interface_id = aws_network_interface.neuwerk_mgmt[0].id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.neuwerk_data[0].id
    device_index         = 1
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 40
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/cloud-init/neuwerk.yaml.tmpl", {
    admin_username                      = var.admin_username
    cloud_provider                      = "aws"
    dns_target_ips                      = local.dns_target_ips
    dns_upstreams                       = local.dns_upstreams
    dns_zone_name                       = var.dns_zone_name
    internal_cidr                       = var.consumer_subnet_cidr
    snat_mode                           = var.neuwerk_snat_mode
    dpdk_workers                        = var.neuwerk_dpdk_workers
    encap_mode                          = local.neuwerk_encap
    encap_mtu                           = var.neuwerk_encap_mtu
    dpdk_mbuf_data_room                 = var.neuwerk_dpdk_mbuf_data_room
    dpdk_port_mtu                       = local.dpdk_port_mtu
    dpdk_queue_override                 = var.neuwerk_dpdk_queue_override
    dpdk_state_shards                   = var.neuwerk_dpdk_state_shards
    dpdk_overlay_debug                  = var.neuwerk_dpdk_overlay_debug
    use_gwlb                            = local.use_gwlb
    s3_bucket                           = aws_s3_bucket.neuwerk.id
    s3_object                           = aws_s3_object.neuwerk_binary.key
    runtime_enabled                     = local.runtime_enabled
    s3_runtime_object                   = var.neuwerk_dpdk_runtime_object_key
    aws_region                          = var.region
    integration_mode                    = "none"
    integration_drain_timeout_secs      = 300
    integration_reconcile_interval_secs = 15
    aws_vpc_id                          = aws_vpc.main.id
    aws_asg_name                        = local.neuwerk_asg_name
    asg_target_group_arn                = ""
  })
  user_data_replace_on_change = true

  tags = local.neuwerk_tag_set

  depends_on = [
    aws_s3_object.neuwerk_binary,
    aws_s3_object.neuwerk_runtime_bundle
  ]
}

resource "aws_lb_target_group" "neuwerk" {
  count       = local.use_gwlb ? 1 : 0
  name_prefix = "nwkgw"
  port        = 6081
  protocol    = "GENEVE"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    protocol            = "TCP"
    port                = "8080"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = merge(var.tags, { Name = "${local.name_prefix}-gwlb-tg" })
}

resource "aws_launch_template" "neuwerk" {
  count       = local.use_gwlb ? 1 : 0
  name_prefix = "${local.name_prefix}-fw-"
  image_id    = local.neuwerk_ami_id

  instance_type = var.neuwerk_instance_type
  key_name      = aws_key_pair.main.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.neuwerk.name
  }

  network_interfaces {
    device_index          = 0
    subnet_id             = aws_subnet.mgmt.id
    security_groups       = [aws_security_group.neuwerk_mgmt.id]
    delete_on_termination = true
  }

  network_interfaces {
    device_index          = 1
    subnet_id             = aws_subnet.dataplane.id
    security_groups       = [aws_security_group.neuwerk_data.id]
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = 40
      volume_type = "gp3"
    }
  }

  user_data = base64encode(templatefile("${path.module}/cloud-init/neuwerk.yaml.tmpl", {
    admin_username                      = var.admin_username
    cloud_provider                      = "aws"
    dns_target_ips                      = local.dns_target_ips
    dns_upstreams                       = local.dns_upstreams
    dns_zone_name                       = var.dns_zone_name
    internal_cidr                       = var.consumer_subnet_cidr
    snat_mode                           = var.neuwerk_snat_mode
    dpdk_workers                        = var.neuwerk_dpdk_workers
    encap_mode                          = local.neuwerk_encap
    encap_mtu                           = var.neuwerk_encap_mtu
    dpdk_mbuf_data_room                 = var.neuwerk_dpdk_mbuf_data_room
    dpdk_port_mtu                       = local.dpdk_port_mtu
    dpdk_queue_override                 = var.neuwerk_dpdk_queue_override
    dpdk_state_shards                   = var.neuwerk_dpdk_state_shards
    dpdk_overlay_debug                  = var.neuwerk_dpdk_overlay_debug
    use_gwlb                            = local.use_gwlb
    s3_bucket                           = aws_s3_bucket.neuwerk.id
    s3_object                           = aws_s3_object.neuwerk_binary.key
    runtime_enabled                     = local.runtime_enabled
    s3_runtime_object                   = var.neuwerk_dpdk_runtime_object_key
    aws_region                          = var.region
    integration_mode                    = "aws-asg"
    integration_drain_timeout_secs      = max(300, var.neuwerk_asg_heartbeat_timeout_secs - 60)
    integration_reconcile_interval_secs = 5
    aws_vpc_id                          = aws_vpc.main.id
    aws_asg_name                        = local.neuwerk_asg_name
    asg_target_group_arn                = aws_lb_target_group.neuwerk[0].arn
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name = "${local.name_prefix}-neuwerk"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(var.tags, {
      Name = "${local.name_prefix}-neuwerk"
    })
  }

  update_default_version = true

  depends_on = [
    aws_s3_object.neuwerk_binary,
    aws_s3_object.neuwerk_runtime_bundle
  ]
}

resource "aws_autoscaling_group" "neuwerk" {
  count               = local.use_gwlb ? 1 : 0
  name                = local.neuwerk_asg_name
  min_size            = var.neuwerk_asg_min_size
  max_size            = var.neuwerk_asg_max_size
  desired_capacity    = var.neuwerk_asg_desired_capacity
  health_check_type   = "EC2"
  force_delete        = true
  vpc_zone_identifier = [aws_subnet.mgmt.id]

  launch_template {
    id      = aws_launch_template.neuwerk[0].id
    version = "$Latest"
  }

  dynamic "tag" {
    for_each = merge(var.tags, { Name = "${local.name_prefix}-neuwerk" })
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

resource "aws_autoscaling_lifecycle_hook" "neuwerk_terminating" {
  count                  = local.use_gwlb ? 1 : 0
  name                   = "${local.name_prefix}-fw-terminating"
  autoscaling_group_name = aws_autoscaling_group.neuwerk[0].name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  heartbeat_timeout      = var.neuwerk_asg_heartbeat_timeout_secs
  default_result         = "CONTINUE"
}

resource "aws_lb" "neuwerk" {
  count              = local.use_gwlb ? 1 : 0
  name               = substr(replace("${local.name_prefix}-gwlb", "_", "-"), 0, 32)
  load_balancer_type = "gateway"
  subnets            = [aws_subnet.dataplane.id]
  tags               = merge(var.tags, { Name = "${local.name_prefix}-gwlb" })
}

resource "aws_lb_listener" "neuwerk" {
  count             = local.use_gwlb ? 1 : 0
  load_balancer_arn = aws_lb.neuwerk[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.neuwerk[0].arn
  }
}

resource "aws_vpc_endpoint_service" "gwlb" {
  count                      = local.use_gwlb ? 1 : 0
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.neuwerk[0].arn]
  supported_ip_address_types = ["ipv4"]
  tags                       = merge(var.tags, { Name = "${local.name_prefix}-gwlb-svc" })
}

resource "aws_vpc_endpoint" "consumer" {
  count             = local.use_gwlb ? 1 : 0
  vpc_id            = aws_vpc.main.id
  service_name      = aws_vpc_endpoint_service.gwlb[0].service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.gwlbe_consumer[0].id]
  tags              = merge(var.tags, { Name = "${local.name_prefix}-gwlbe-consumer" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_endpoint" "upstream" {
  count             = local.use_gwlb ? 1 : 0
  vpc_id            = aws_vpc.main.id
  service_name      = aws_vpc_endpoint_service.gwlb[0].service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.gwlbe_upstream[0].id]
  tags              = merge(var.tags, { Name = "${local.name_prefix}-gwlbe-upstream" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_instance" "upstream" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.upstream_instance_type
  subnet_id                   = aws_subnet.upstream.id
  private_ip                  = var.upstream_private_ip
  key_name                    = aws_key_pair.main.key_name
  vpc_security_group_ids      = [aws_security_group.upstream.id]
  associate_public_ip_address = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/cloud-init/upstream.yaml.tmpl", {
    dns_zone_name    = var.dns_zone_name
    upstream_ip_addr = var.upstream_private_ip
    vpc_cidr         = var.vpc_cidr
    endpoint_mtu     = local.endpoint_mtu
  })
  user_data_replace_on_change = true

  tags = merge(var.tags, { Name = "${local.name_prefix}-upstream" })
}

resource "aws_instance" "consumer" {
  count                       = var.consumer_count
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.consumer_instance_type
  subnet_id                   = aws_subnet.consumer.id
  key_name                    = aws_key_pair.main.key_name
  vpc_security_group_ids      = [aws_security_group.consumer.id]
  associate_public_ip_address = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/cloud-init/consumer.yaml.tmpl", {
    endpoint_mtu = local.endpoint_mtu
  })
  user_data_replace_on_change = true

  tags = merge(var.tags, { Name = "${local.name_prefix}-consumer-${count.index}" })
}

resource "aws_instance" "jumpbox" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.jumpbox_instance_type
  subnet_id                   = aws_subnet.jumpbox.id
  key_name                    = aws_key_pair.main.key_name
  vpc_security_group_ids      = [aws_security_group.jumpbox.id]
  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 16
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/cloud-init/jumpbox.yaml.tmpl", {})

  tags = merge(var.tags, { Name = "${local.name_prefix}-jumpbox" })
}
