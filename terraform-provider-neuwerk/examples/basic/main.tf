terraform {
  required_providers {
    neuwerk = {
      source = "moolen/neuwerk"
    }
  }
}

provider "neuwerk" {
  endpoints       = ["https://fw-a.example.com", "https://fw-b.example.com"]
  token           = var.neuwerk_bootstrap_token
  ca_cert_pem     = file("${path.module}/neuwerk-ca.crt")
  request_timeout = "30s"
  retry_timeout   = "5s"
}

resource "neuwerk_service_account" "terraform" {
  name  = "terraform"
  role = "admin"
}

resource "neuwerk_service_account_token" "terraform" {
  service_account_id = neuwerk_service_account.terraform.id
  name               = "terraform"
  role    = "admin"
  eternal = true
}

resource "neuwerk_kubernetes_integration" "prod" {
  name                  = "prod-k8s"
  api_server_url        = "https://10.0.0.10:6443"
  ca_cert_pem           = file("${path.module}/k8s-ca.pem")
  service_account_token = var.k8s_service_account_token
}

resource "neuwerk_tls_intercept_ca" "main" {
  generate = true
}

variable "k8s_service_account_token" {
  type      = string
  sensitive = true
}

variable "neuwerk_bootstrap_token" {
  type      = string
  sensitive = true
}
