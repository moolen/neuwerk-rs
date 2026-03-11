resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  name_suffix               = random_string.suffix.result
  name_prefix               = "${var.name_prefix}-${local.name_suffix}"
  firewall_igm              = "${local.name_prefix}-fw-mig"
  bucket_name               = substr(replace(replace(lower("${var.name_prefix}-${local.name_suffix}"), "_", "-"), ".", "-"), 0, 63)
  ssh_public_key            = file(var.ssh_public_key_path)
  ssh_metadata              = "${var.admin_username}:${local.ssh_public_key}"
  dns_target_ips            = length(var.dns_target_ips) > 0 ? var.dns_target_ips : ["$${MGMT_IP}"]
  dns_upstreams             = length(var.dns_upstreams) > 0 ? var.dns_upstreams : ["${var.upstream_vm_ip}:53"]
  firewall_mgmt_queue_count = max(1, var.firewall_mgmt_queue_count)
  firewall_dataplane_queue_count = max(
    1,
    var.firewall_total_nic_queue_count - local.firewall_mgmt_queue_count
  )
}

resource "google_compute_network" "main" {
  name                    = "${local.name_prefix}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "mgmt" {
  name          = "${local.name_prefix}-mgmt"
  ip_cidr_range = var.mgmt_subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "dataplane" {
  name          = "${local.name_prefix}-dataplane"
  ip_cidr_range = var.dataplane_subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "consumer" {
  name          = "${local.name_prefix}-consumer"
  ip_cidr_range = var.consumer_subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "upstream" {
  name          = "${local.name_prefix}-upstream"
  ip_cidr_range = var.upstream_subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "jumpbox" {
  name          = "${local.name_prefix}-jumpbox"
  ip_cidr_range = var.jumpbox_subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id
}

resource "google_compute_router" "nat" {
  name    = "${local.name_prefix}-nat-router"
  network = google_compute_network.main.id
  region  = var.region
}

resource "google_compute_router_nat" "nat" {
  name                               = "${local.name_prefix}-nat"
  router                             = google_compute_router.nat.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

resource "google_service_account" "firewall" {
  account_id   = substr(replace("${local.name_prefix}-fw", "_", "-"), 0, 30)
  display_name = "Neuwerk GCP firewall"
}

resource "google_storage_bucket" "firewall" {
  name                        = local.bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
}

resource "google_storage_bucket_object" "firewall" {
  bucket = google_storage_bucket.firewall.name
  name   = var.firewall_blob_name
  source = var.firewall_binary_path
}

resource "google_storage_bucket_object" "firewall_dpdk_runtime" {
  bucket = google_storage_bucket.firewall.name
  name   = var.firewall_dpdk_runtime_blob_name
  source = var.firewall_dpdk_runtime_bundle_path
}

resource "google_storage_bucket_iam_member" "firewall_reader" {
  bucket = google_storage_bucket.firewall.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.firewall.email}"
}

resource "google_project_iam_member" "firewall_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.firewall.email}"
}

resource "google_compute_firewall" "allow_internal" {
  name    = "${local.name_prefix}-allow-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "all"
  }

  source_ranges = [var.vpc_cidr]
}

resource "google_compute_firewall" "jumpbox_admin_ssh" {
  name    = "${local.name_prefix}-jumpbox-admin-ssh"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [var.admin_cidr]
  target_tags   = ["neuwerk-jumpbox"]
}

resource "google_compute_firewall" "allow_ssh_from_jumpbox" {
  name    = "${local.name_prefix}-allow-ssh-from-jumpbox"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [var.jumpbox_subnet_cidr]
  target_tags   = ["neuwerk-firewall", "neuwerk-consumer", "neuwerk-upstream"]
}

resource "google_compute_firewall" "allow_health_checks" {
  name    = "${local.name_prefix}-allow-health-checks"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8080", "8443"]
  }

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
  target_tags   = ["neuwerk-firewall", "neuwerk-upstream"]
}

resource "google_compute_health_check" "firewall" {
  name = "${local.name_prefix}-fw-hc"

  tcp_health_check {
    port = 8080
  }
}

resource "google_compute_instance_template" "firewall" {
  name_prefix    = "${local.name_prefix}-fw-tpl-"
  machine_type   = var.firewall_machine_type
  can_ip_forward = true

  lifecycle {
    create_before_destroy = true
  }

  disk {
    source_image = "projects/${var.image_project}/global/images/family/${var.image_family}"
    auto_delete  = true
    boot         = true
    disk_size_gb = var.boot_disk_size_gb
    disk_type    = "pd-balanced"
  }

  network_interface {
    subnetwork  = google_compute_subnetwork.dataplane.id
    nic_type    = "GVNIC"
    queue_count = local.firewall_dataplane_queue_count
  }

  network_interface {
    subnetwork  = google_compute_subnetwork.mgmt.id
    nic_type    = "GVNIC"
    queue_count = local.firewall_mgmt_queue_count
  }

  metadata = {
    user-data = templatefile("${path.module}/cloud-init/firewall.yaml.tmpl", {
      gcs_bucket            = google_storage_bucket.firewall.name
      gcs_object            = google_storage_bucket_object.firewall.name
      gcs_dpdk_object       = google_storage_bucket_object.firewall_dpdk_runtime.name
      dns_zone_name         = var.dns_zone_name
      dns_target_ips        = local.dns_target_ips
      dns_upstreams         = local.dns_upstreams
      internal_cidr         = var.consumer_subnet_cidr
      snat_mode             = var.firewall_snat_mode
      dpdk_workers          = var.firewall_dpdk_workers
      cloud_provider        = var.cloud_provider
      mgmt_subnet_cidr      = var.mgmt_subnet_cidr
      dataplane_subnet_cidr = var.dataplane_subnet_cidr
      vpc_cidr              = var.vpc_cidr
      gcp_project           = var.project_id
      gcp_region            = var.region
      gcp_ig_name           = local.firewall_igm
    })
    ssh-keys       = local.ssh_metadata
    enable-oslogin = "FALSE"
  }

  service_account {
    email  = google_service_account.firewall.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  labels = var.tags
  tags   = ["neuwerk-firewall", "neuwerk-dataplane"]
}

resource "google_compute_instance_group_manager" "firewall" {
  name               = local.firewall_igm
  zone               = var.zone
  base_instance_name = "${local.name_prefix}-fw"
  target_size        = var.firewall_instance_count
  wait_for_instances = false

  version {
    instance_template = google_compute_instance_template.firewall.id
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 1
    max_unavailable_fixed = 0
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.firewall.id
    initial_delay_sec = 120
  }
}

resource "google_compute_region_backend_service" "dataplane" {
  name                  = "${local.name_prefix}-dataplane-bs"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  protocol              = "UNSPECIFIED"
  health_checks         = [google_compute_health_check.firewall.id]
  network               = google_compute_network.main.id

  backend {
    group = google_compute_instance_group_manager.firewall.instance_group
  }
}

resource "google_compute_address" "dataplane_ilb" {
  name         = "${local.name_prefix}-dataplane-ilb"
  region       = var.region
  subnetwork   = google_compute_subnetwork.dataplane.id
  address_type = "INTERNAL"
  address      = var.dataplane_lb_ip
}

resource "google_compute_forwarding_rule" "dataplane" {
  name                  = "${local.name_prefix}-dataplane-fr"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  ip_protocol           = "L3_DEFAULT"
  all_ports             = true
  allow_global_access   = true
  network               = google_compute_network.main.id
  subnetwork            = google_compute_subnetwork.dataplane.id
  ip_address            = google_compute_address.dataplane_ilb.address
  backend_service       = google_compute_region_backend_service.dataplane.id
}

resource "google_compute_address" "dataplane_consumer_ilb" {
  name         = "${local.name_prefix}-dataplane-consumer-ilb"
  region       = var.region
  subnetwork   = google_compute_subnetwork.consumer.id
  address_type = "INTERNAL"
  address      = var.consumer_dataplane_lb_ip
}

resource "google_compute_forwarding_rule" "dataplane_consumer" {
  name                  = "${local.name_prefix}-dataplane-consumer-fr"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  ip_protocol           = "L3_DEFAULT"
  all_ports             = true
  allow_global_access   = true
  network               = google_compute_network.main.id
  subnetwork            = google_compute_subnetwork.consumer.id
  ip_address            = google_compute_address.dataplane_consumer_ilb.address
  backend_service       = google_compute_region_backend_service.dataplane.id
}

resource "google_compute_address" "dataplane_upstream_ilb" {
  name         = "${local.name_prefix}-dataplane-upstream-ilb"
  region       = var.region
  subnetwork   = google_compute_subnetwork.upstream.id
  address_type = "INTERNAL"
  address      = var.upstream_dataplane_lb_ip
}

resource "google_compute_forwarding_rule" "dataplane_upstream" {
  name                  = "${local.name_prefix}-dataplane-upstream-fr"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  ip_protocol           = "L3_DEFAULT"
  all_ports             = true
  allow_global_access   = true
  network               = google_compute_network.main.id
  subnetwork            = google_compute_subnetwork.upstream.id
  ip_address            = google_compute_address.dataplane_upstream_ilb.address
  backend_service       = google_compute_region_backend_service.dataplane.id
}

resource "google_network_connectivity_policy_based_route" "consumer_to_upstream" {
  provider = google-beta

  name            = "${local.name_prefix}-pbr-consumer-upstream"
  network         = google_compute_network.main.id
  priority        = 100
  next_hop_ilb_ip = google_compute_address.dataplane_consumer_ilb.address

  filter {
    protocol_version = "IPV4"
    dest_range       = var.upstream_subnet_cidr
  }

  virtual_machine {
    tags = ["neuwerk-consumer"]
  }
}

resource "google_compute_instance" "upstream" {
  name                      = "${local.name_prefix}-upstream"
  zone                      = var.zone
  machine_type              = var.upstream_machine_type
  allow_stopping_for_update = true
  can_ip_forward            = false

  boot_disk {
    initialize_params {
      image = "projects/${var.image_project}/global/images/family/${var.image_family}"
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.upstream.id
    network_ip = var.upstream_vm_ip
    nic_type   = "GVNIC"
  }

  metadata = {
    user-data = templatefile("${path.module}/cloud-init/upstream.yaml.tmpl", {
      dns_zone_name    = var.dns_zone_name
      upstream_ip_addr = var.upstream_lb_ip
    })
    ssh-keys       = local.ssh_metadata
    enable-oslogin = "FALSE"
  }

  labels = var.tags
  tags   = ["neuwerk-upstream", "upstream"]
}

resource "google_network_connectivity_policy_based_route" "upstream_to_consumers" {
  provider = google-beta

  name            = "${local.name_prefix}-pbr-upstream-consumers"
  network         = google_compute_network.main.id
  priority        = 100
  next_hop_ilb_ip = google_compute_address.dataplane_upstream_ilb.address

  filter {
    protocol_version = "IPV4"
    dest_range       = var.consumer_subnet_cidr
  }

  virtual_machine {
    tags = ["neuwerk-upstream"]
  }
}

resource "google_compute_instance_group" "upstream" {
  name      = "${local.name_prefix}-upstream-ig"
  zone      = var.zone
  network   = google_compute_network.main.id
  instances = [google_compute_instance.upstream.self_link]
}

resource "google_compute_health_check" "upstream" {
  name = "${local.name_prefix}-upstream-hc"

  tcp_health_check {
    port = 80
  }
}

resource "google_compute_region_backend_service" "upstream" {
  name                  = "${local.name_prefix}-upstream-bs"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  protocol              = "UNSPECIFIED"
  health_checks         = [google_compute_health_check.upstream.id]
  network               = google_compute_network.main.id

  backend {
    group = google_compute_instance_group.upstream.id
  }
}

resource "google_compute_address" "upstream_ilb" {
  name         = "${local.name_prefix}-upstream-ilb"
  region       = var.region
  subnetwork   = google_compute_subnetwork.upstream.id
  address_type = "INTERNAL"
  address      = var.upstream_lb_ip
}

resource "google_compute_forwarding_rule" "upstream" {
  name                  = "${local.name_prefix}-upstream-fr"
  region                = var.region
  load_balancing_scheme = "INTERNAL"
  ip_protocol           = "L3_DEFAULT"
  all_ports             = true
  allow_global_access   = true
  network               = google_compute_network.main.id
  subnetwork            = google_compute_subnetwork.upstream.id
  ip_address            = google_compute_address.upstream_ilb.address
  backend_service       = google_compute_region_backend_service.upstream.id
}

resource "google_compute_instance" "consumer" {
  count                     = var.consumer_count
  name                      = "${local.name_prefix}-consumer-${count.index}"
  zone                      = var.zone
  machine_type              = var.consumer_machine_type
  allow_stopping_for_update = true
  can_ip_forward            = false

  boot_disk {
    initialize_params {
      image = "projects/${var.image_project}/global/images/family/${var.image_family}"
      size  = var.boot_disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.consumer.id
    nic_type   = "GVNIC"
  }

  metadata = {
    user-data      = templatefile("${path.module}/cloud-init/consumer.yaml.tmpl", {})
    ssh-keys       = local.ssh_metadata
    enable-oslogin = "FALSE"
  }

  labels = var.tags
  tags   = ["neuwerk-consumer", "consumer"]
}

resource "google_compute_instance" "jumpbox" {
  name                      = "${local.name_prefix}-jumpbox"
  zone                      = var.zone
  machine_type              = var.jumpbox_machine_type
  allow_stopping_for_update = true
  can_ip_forward            = false

  boot_disk {
    initialize_params {
      image = "projects/${var.image_project}/global/images/family/${var.image_family}"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.jumpbox.id
    nic_type   = "GVNIC"

    access_config {}
  }

  metadata = {
    user-data      = file("${path.module}/cloud-init/jumpbox.yaml.tmpl")
    ssh-keys       = local.ssh_metadata
    enable-oslogin = "FALSE"
  }

  labels = var.tags
  tags   = ["neuwerk-jumpbox"]
}
