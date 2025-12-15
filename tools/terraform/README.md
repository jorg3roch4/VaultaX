# VaultaX - Terraform Configuration

This Terraform configuration sets up HashiCorp Vault with all secrets required for VaultaX samples.

## Prerequisites

- [Terraform](https://www.terraform.io/downloads) >= 1.0.0
- [HashiCorp Vault](https://www.vaultproject.io/) server running
- Vault token with admin privileges

## Quick Start

### 1. Start Vault (Development Mode)

```bash
# Using Docker
docker run -d --name vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  hashicorp/vault:latest

# Or use the docker-compose in NetNest/docker/Vault
```

### 2. Set Environment Variables

```bash
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="root"
```

### 3. Initialize and Apply

```bash
cd tools/terraform

# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Apply configuration
terraform apply
```

## Configuration

### Using Default Values

The configuration includes sensible defaults for development. Simply run:

```bash
terraform apply -auto-approve
```

### Custom Values

1. Copy the example file:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

2. Edit `terraform.tfvars` with your values

3. Apply:
   ```bash
   terraform apply
   ```

### Production Secrets

To also create production secrets:

```bash
terraform apply -var="create_production_secrets=true"
```

Or set in `terraform.tfvars`:
```hcl
create_production_secrets = true
prod_db_connection_string = "Server=prod-db..."
# ... other production variables
```

## What Gets Created

### Secrets Engine
- **Transit** engine at `transit/` for encryption and signing

### Transit Keys
| Key Name | Type | Purpose |
|----------|------|---------|
| `sample-signing-key` | RSA-2048 | Document signing |

### KV Secrets (v2)
| Path | Keys | Description |
|------|------|-------------|
| `secret/sample/demo` | username, password, api_key | Console sample |
| `secret/development/database` | connectionString, password | Dev database |
| `secret/development/rabbitmq` | host, username, password, virtualHost | Dev RabbitMQ |
| `secret/development/jwt` | secret, issuer, audience | Dev JWT config |
| `secret/production/*` | (same as development) | Production (optional) |

## Verify Secrets

After applying, verify the secrets were created:

```bash
# List secrets
vault kv list secret/sample
vault kv list secret/development

# Read a secret
vault kv get secret/sample/demo

# Check Transit key
vault read transit/keys/sample-signing-key
```

## Destroy

To remove all created resources:

```bash
terraform destroy
```

## Security Notes

- **Never commit** `terraform.tfvars` to source control
- Use **environment variables** or **Vault** for production secrets
- In CI/CD, pass secrets via `-var` flags or environment variables:
  ```bash
  terraform apply \
    -var="prod_db_password=$DB_PASSWORD" \
    -var="prod_jwt_secret=$JWT_SECRET"
  ```

## File Structure

```
tools/terraform/
├── main.tf                    # Main configuration
├── variables.tf               # Variable definitions
├── outputs.tf                 # Output values
├── terraform.tfvars.example   # Example variables file
└── README.md                  # This file
```

## Recommended .gitignore

Add these patterns to your `.gitignore` to prevent committing sensitive Terraform files:

```gitignore
# Terraform
**/.terraform/
*.tfstate
*.tfstate.*
*.tfvars
!*.tfvars.example
*.tfplan
.terraform.lock.hcl
```
