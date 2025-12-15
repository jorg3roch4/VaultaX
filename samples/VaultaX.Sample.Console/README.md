# VaultaX Console Sample

This sample demonstrates how to use VaultaX to interact with HashiCorp Vault from a .NET console application.

## Features Demonstrated

1. **Key-Value Engine**: Reading secrets from Vault's KV secrets engine
2. **Transit Engine**: Signing data with Vault's Transit engine (private key never leaves Vault)
3. **Signature Verification**: Verifying signed data

## Prerequisites

1. **HashiCorp Vault**: Running locally or remotely
2. **Vault Token**: Authentication token with appropriate permissions
3. **.NET 10 SDK**: Required to build and run the application

## Setup

### 1. Start Vault (Development Mode)

For testing, you can run Vault in development mode:

```bash
vault server -dev
```

Note the Root Token displayed in the output. You'll need this for authentication.

### 2. Set Environment Variable

Set your Vault token as an environment variable:

```bash
# Linux/macOS
export VAULT_TOKEN=your-vault-token-here

# Windows (PowerShell)
$env:VAULT_TOKEN = "your-vault-token-here"

# Windows (CMD)
set VAULT_TOKEN=your-vault-token-here
```

### 3. Create Sample Secrets (Optional)

Create a sample secret for the KV engine demonstration:

```bash
vault kv put secret/sample/demo \
  username=admin \
  password=secret123 \
  api_key=my-api-key-value
```

### 4. Create Transit Signing Key (Optional)

Create a signing key for the Transit engine demonstration:

```bash
# Create a Transit key for signing
vault write transit/keys/sample-signing-key type=rsa-2048
```

## Configuration

Edit `appsettings.json` or `appsettings.Development.json` to configure VaultaX:

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "http://localhost:8200",
    "MountPoint": "secret",
    "KvVersion": 2,
    "BasePath": "",
    "Authentication": {
      "Method": "Token",
      "Token": "env:VAULT_TOKEN"
    }
  }
}
```

### Configuration Options

- **Enabled**: Set to `true` to enable VaultaX integration
- **Address**: Vault server URL (default: `http://localhost:8200` for dev mode)
- **MountPoint**: KV secrets engine mount point (default: `secret`)
- **KvVersion**: KV engine version, either `1` or `2` (default: `2`)
- **BasePath**: Optional path prefix for all secrets
- **Authentication.Method**: Auth method (`Token`, `AppRole`, `Kubernetes`, etc.)
- **Authentication.Token**: Vault token (use `env:VARIABLE_NAME` to read from environment)

## Running the Sample

### Development Mode (Vault Enabled)

```bash
dotnet run --project VaultaX.Sample.Console.csproj --environment Development
```

### Production Mode (Vault Disabled)

By default, the sample will show a warning if VaultaX is disabled:

```bash
dotnet run --project VaultaX.Sample.Console.csproj
```

## Expected Output

When running with Vault enabled and properly configured:

```
 _   __          _ _
| | / /         | | |
| |/ / __ _ _  _| | |_ __ X
|    \ / _` | || | | __/ _` |
| |\  \ (_| | \__,_|_|\__\__,|
\_| \_/\__,_|

VaultaX - HashiCorp Vault Integration for .NET

Reading secrets from Vault KV engine...
Reading secret from path: sample/demo
┌──────────┬────────────────────┐
│ Key      │ Value              │
├──────────┼────────────────────┤
│ username │ admin              │
│ password │ secret123          │
│ api_key  │ my-api-key-value   │
└──────────┴────────────────────┘

Signing data with Vault Transit engine...
Using Transit key: sample-signing-key
Document to sign: This is a sample document to be signed

✓ Key exists: rsa-2048 (version 1)

✓ Data signed successfully!
Signature: vault:v1:MEUCIQDexample...
Key version used: 1

✓ Signature verification: VALID

Tampered data verification: INVALID (as expected)

┌─────────────────────────────────────────────────────────────┐
│ Transit Engine Benefits                                     │
├─────────────────────────────────────────────────────────────┤
│ The Transit engine provides cryptographic operations        │
│ without exposing private keys.                              │
│ Private keys never leave Vault, making it ideal for secure  │
│ signing operations.                                          │
└─────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### "VaultaX is disabled in configuration"

- Ensure `VaultaX:Enabled` is set to `true` in your appsettings file
- Run with `--environment Development` to use `appsettings.Development.json`

### "Secret not found at path"

- Create the sample secret using the Vault CLI (see Setup step 3)
- Verify the secret path matches your configuration (check `BasePath` setting)

### "Transit key not found"

- Create the Transit signing key using the Vault CLI (see Setup step 4)
- Ensure the Transit secrets engine is enabled: `vault secrets enable transit`

### Authentication Errors

- Verify your `VAULT_TOKEN` environment variable is set correctly
- Ensure the token has read permissions for `secret/*` and `transit/*`
- Check token validity: `vault token lookup`

## Using with Production Vault

For production use, update your configuration to use AppRole or another production-ready authentication method:

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.example.com:8200",
    "Authentication": {
      "Method": "AppRole",
      "RoleId": "env:VAULT_ROLE_ID",
      "SecretId": "env:VAULT_SECRET_ID"
    }
  }
}
```

## Learn More

- [VaultaX Documentation](../../README.md)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Vault Transit Secrets Engine](https://www.vaultproject.io/docs/secrets/transit)
- [Vault KV Secrets Engine](https://www.vaultproject.io/docs/secrets/kv)
