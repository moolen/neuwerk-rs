terraform {
  required_providers {
    neuwerk = {
      source = "neuwerk/neuwerk"
    }
  }
}

provider "neuwerk" {
  endpoints    = ["https://fw-a.example.com"]
  token        = var.neuwerk_admin_token
  ca_cert_pem  = file("${path.module}/neuwerk-ca.crt")
}

resource "neuwerk_service_account" "automation" {
  name        = "terraform-automation"
  description = "automation identity"
  role        = "admin"
}

resource "neuwerk_service_account_token" "automation" {
  service_account_id = neuwerk_service_account.automation.id
  name               = "terraform-admin"
  role               = "admin"
  eternal            = true
}

variable "neuwerk_admin_token" {
  type      = string
  sensitive = true
}
