# =============================================================================
# VaultaX - Terraform Outputs
# =============================================================================

output "transit_key_name" {
  description = "Name of the Transit signing key"
  value       = vault_transit_secret_backend_key.sample_signing_key.name
}

output "transit_key_type" {
  description = "Type of the Transit signing key"
  value       = vault_transit_secret_backend_key.sample_signing_key.type
}

output "secrets_created" {
  description = "List of KV secrets created"
  value = [
    "secret/data/sample/demo",
    "secret/data/development/database",
    "secret/data/development/rabbitmq",
    "secret/data/development/jwt",
  ]
}

output "production_secrets_created" {
  description = "Whether production secrets were created"
  value       = var.create_production_secrets
}

output "vault_paths" {
  description = "Vault paths for VaultaX configuration"
  value = {
    kv_mount_point = "secret"
    transit_mount  = vault_mount.transit.path
    base_paths     = ["sample", "development", "production"]
  }
}
