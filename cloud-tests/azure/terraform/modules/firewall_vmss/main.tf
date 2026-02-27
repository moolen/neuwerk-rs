locals {
  vmss_name = var.azure_vmss_name
}

resource "azurerm_user_assigned_identity" "firewall" {
  name                = "${var.name_prefix}-fw-id"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_orchestrated_virtual_machine_scale_set" "firewall" {
  name                        = local.vmss_name
  resource_group_name         = var.resource_group_name
  location                    = var.location
  sku_name                    = var.vm_size
  instances                   = var.instance_count
  upgrade_mode                = "Manual"
  platform_fault_domain_count = 1
  tags                        = var.tags

  source_image_reference {
    publisher = var.image_publisher
    offer     = var.image_offer
    sku       = var.image_sku
    version   = var.image_version
  }

  os_disk {
    storage_account_type = "Premium_LRS"
    caching              = "ReadWrite"
  }

  os_profile {
    custom_data = base64encode(templatefile("${path.module}/../../cloud-init/firewall.yaml.tmpl", {
      storage_account_name   = var.storage_account_name
      storage_container_name = var.storage_container_name
      storage_blob_name      = var.storage_blob_name
      dns_zone_name          = var.dns_zone_name
      dns_upstream_ip        = var.dns_upstream_ip
      gwlb_vni_internal      = var.gwlb_vni_internal
      gwlb_vni_external      = var.gwlb_vni_external
      gwlb_udp_port_internal = var.gwlb_udp_port_internal
      gwlb_udp_port_external = var.gwlb_udp_port_external
      internal_cidr          = var.internal_cidr
      snat_mode              = var.snat_mode
      dpdk_workers           = var.dpdk_workers
      azure_subscription_id  = var.azure_subscription_id
      azure_resource_group   = var.azure_resource_group
      azure_vmss_name        = local.vmss_name
      cloud_provider         = var.cloud_provider
      identity_client_id     = azurerm_user_assigned_identity.firewall.client_id
    }))

    linux_configuration {
      admin_username                  = var.admin_username
      disable_password_authentication = true

      admin_ssh_key {
        username   = var.admin_username
        public_key = var.ssh_public_key
      }
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.firewall.id]
  }

  termination_notification {
    enabled = true
    timeout = "PT5M"
  }

  network_interface {
    name                          = "mgmt0"
    primary                       = true
    enable_accelerated_networking = false

    ip_configuration {
      name      = "mgmt-ipcfg"
      primary   = true
      subnet_id = var.mgmt_subnet_id
      load_balancer_backend_address_pool_ids = [var.mgmt_lb_backend_pool_id]
    }
  }

  network_interface {
    name                          = "data0"
    primary                       = false
    enable_ip_forwarding          = true
    enable_accelerated_networking = true

    ip_configuration {
      name                                   = "data-ipcfg"
      primary                                = true
      subnet_id                              = var.dataplane_subnet_id
      load_balancer_backend_address_pool_ids = [var.dataplane_lb_backend_pool_id]
    }
  }
}
