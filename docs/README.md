# VaultaX Documentation

Complete documentation for VaultaX — .NET library for HashiCorp Vault integration.

## Guides

| # | Guide | Description |
|---|-------|-------------|
| 01 | [Getting Started](guides/01-getting-started.md) | Basic setup and first use |
| 02 | [Configuration](guides/02-configuration.md) | All configuration options |
| 03 | [Authentication](guides/03-authentication.md) | Supported authentication methods |
| 04 | [Secret Engines](guides/04-secret-engines.md) | KV, Transit, and PKI engines |
| 05 | [Signing](guides/05-signing.md) | Complete guide for document signing |
| 06 | [Hot Reload](guides/06-hot-reload.md) | Automatic secret reloading |
| 07 | [Health Checks](guides/07-health-checks.md) | Health monitoring |
| 08 | [Examples](guides/08-examples.md) | Common use cases |
| 09 | [Migration](guides/09-migration.md) | Migrating from existing implementations |
| 10 | [Troubleshooting](guides/10-troubleshooting.md) | Problem solving |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Application                         │
├─────────────────────────────────────────────────────────────────┤
│  IConfiguration  │  IKeyValueEngine  │  ITransitEngine  │  ... │
├─────────────────────────────────────────────────────────────────┤
│                         VaultaX                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ Config      │  │ Secret      │  │ Background Services     │ │
│  │ Provider    │  │ Engines     │  │ - Token Renewal         │ │
│  │             │  │ - KV        │  │ - Secret Change Watcher │ │
│  │             │  │ - Transit   │  │                         │ │
│  │             │  │ - PKI       │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                       VaultSharp                                │
├─────────────────────────────────────────────────────────────────┤
│                    HashiCorp Vault                              │
└─────────────────────────────────────────────────────────────────┘
```

## Key Features

| Feature | Description |
|---------|-------------|
| Transparent Configuration | Vault secrets override appsettings.json values |
| 12 Auth Methods | Token, AppRole, Kubernetes, LDAP, JWT, AWS, Azure, etc. |
| Hot Reload | Automatic reload when secrets change |
| Token Renewal | Automatic token renewal before expiry |
| Health Checks | Native ASP.NET Core integration |
| Transit Engine | Signing and encryption without exposing private keys |
| PKI Engine | Certificate issuance and management |

## Requirements

- .NET 10.0 or later
- HashiCorp Vault 1.12 or later
- VaultSharp 1.17.x

## License

Apache 2.0
