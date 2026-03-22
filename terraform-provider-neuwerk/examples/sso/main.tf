terraform {
  required_providers {
    neuwerk = {
      source = "neuwerk/neuwerk"
    }
  }
}

provider "neuwerk" {
  endpoints   = ["https://fw-a.example.com"]
  token       = var.neuwerk_admin_token
  ca_cert_pem = file("${path.module}/neuwerk-ca.crt")
}

resource "neuwerk_sso_provider_google" "google" {
  name          = "Corp Google"
  client_id     = var.google_client_id
  client_secret = var.google_client_secret
  scopes        = ["openid", "email", "profile"]
}

resource "neuwerk_sso_provider_github" "github" {
  name          = "Corp GitHub"
  client_id     = var.github_client_id
  client_secret = var.github_client_secret
}

resource "neuwerk_sso_provider_generic_oidc" "oidc" {
  name              = "Corp OIDC"
  client_id         = var.oidc_client_id
  client_secret     = var.oidc_client_secret
  authorization_url = "https://idp.example.com/oauth2/authorize"
  token_url         = "https://idp.example.com/oauth2/token"
  userinfo_url      = "https://idp.example.com/oauth2/userinfo"
}

variable "neuwerk_admin_token" {
  type      = string
  sensitive = true
}

variable "google_client_id" {
  type = string
}

variable "google_client_secret" {
  type      = string
  sensitive = true
}

variable "github_client_id" {
  type = string
}

variable "github_client_secret" {
  type      = string
  sensitive = true
}

variable "oidc_client_id" {
  type = string
}

variable "oidc_client_secret" {
  type      = string
  sensitive = true
}
