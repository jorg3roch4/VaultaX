# =============================================================================
# VaultaX - Terraform Configuration for HashiCorp Vault
# =============================================================================
# This configuration sets up all secrets required for VaultaX samples.
#
# Usage:
#   1. Set environment variables:
#      export VAULT_ADDR="http://localhost:8200"
#      export VAULT_TOKEN="root"
#
#   2. Initialize and apply:
#      terraform init
#      terraform plan
#      terraform apply
#
# =============================================================================

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Provider Configuration
# -----------------------------------------------------------------------------
provider "vault" {
  # Configuration is read from environment variables:
  # - VAULT_ADDR: Vault server address
  # - VAULT_TOKEN: Authentication token
  #
  # Or uncomment below for explicit configuration:
  # address = "http://localhost:8200"
  # token   = "root"
}

# -----------------------------------------------------------------------------
# Enable Transit Secrets Engine
# -----------------------------------------------------------------------------
resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "Transit secrets engine for encryption and signing"
}

# -----------------------------------------------------------------------------
# Transit Signing Key
# -----------------------------------------------------------------------------
resource "vault_transit_secret_backend_key" "sample_signing_key" {
  backend = vault_mount.transit.path
  name    = "sample-signing-key"
  type    = "rsa-2048"

  deletion_allowed = true
}

# -----------------------------------------------------------------------------
# KV Secrets - Console Sample
# -----------------------------------------------------------------------------
resource "vault_kv_secret_v2" "sample_demo" {
  mount = "secret"
  name  = "sample/demo"

  data_json = jsonencode({
    username = var.sample_username
    password = var.sample_password
    api_key  = var.sample_api_key
  })
}

# -----------------------------------------------------------------------------
# KV Secrets - Development Environment
# -----------------------------------------------------------------------------
resource "vault_kv_secret_v2" "development_database" {
  mount = "secret"
  name  = "development/database"

  data_json = jsonencode({
    connectionString = var.dev_db_connection_string
    password         = var.dev_db_password
  })
}

resource "vault_kv_secret_v2" "development_rabbitmq" {
  mount = "secret"
  name  = "development/rabbitmq"

  data_json = jsonencode({
    host        = var.dev_rabbitmq_host
    username    = var.dev_rabbitmq_username
    password    = var.dev_rabbitmq_password
    virtualHost = var.dev_rabbitmq_vhost
  })
}

resource "vault_kv_secret_v2" "development_jwt" {
  mount = "secret"
  name  = "development/jwt"

  data_json = jsonencode({
    secret   = var.dev_jwt_secret
    issuer   = var.dev_jwt_issuer
    audience = var.dev_jwt_audience
  })
}

# -----------------------------------------------------------------------------
# KV Secrets - Production Environment (Example)
# -----------------------------------------------------------------------------
resource "vault_kv_secret_v2" "production_database" {
  count = var.create_production_secrets ? 1 : 0

  mount = "secret"
  name  = "production/database"

  data_json = jsonencode({
    connectionString = var.prod_db_connection_string
    password         = var.prod_db_password
  })
}

resource "vault_kv_secret_v2" "production_rabbitmq" {
  count = var.create_production_secrets ? 1 : 0

  mount = "secret"
  name  = "production/rabbitmq"

  data_json = jsonencode({
    host        = var.prod_rabbitmq_host
    username    = var.prod_rabbitmq_username
    password    = var.prod_rabbitmq_password
    virtualHost = var.prod_rabbitmq_vhost
  })
}

resource "vault_kv_secret_v2" "production_jwt" {
  count = var.create_production_secrets ? 1 : 0

  mount = "secret"
  name  = "production/jwt"

  data_json = jsonencode({
    secret   = var.prod_jwt_secret
    issuer   = var.prod_jwt_issuer
    audience = var.prod_jwt_audience
  })
}
