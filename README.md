![VaultaX Logo](https://raw.githubusercontent.com/jorg3roch4/VaultaX/main/assets/vaultax-brand.png)

# VaultaX

**HashiCorp Vault Integration for .NET 10+**

[![NuGet](https://img.shields.io/nuget/v/VaultaX.svg?style=flat-square)](https://www.nuget.org/packages/VaultaX)[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](https://github.com/jorg3roch4/VaultaX/blob/main/LICENSE)[![C#](https://img.shields.io/badge/C%23-14-239120.svg?style=flat-square)](https://docs.microsoft.com/en-us/dotnet/csharp/)[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4.svg?style=flat-square)](https://dotnet.microsoft.com/)

**VaultaX** is a comprehensive .NET library for seamless HashiCorp Vault integration. It provides transparent secret management where Vault secrets automatically overlay your `appsettings.json` values, automatic token renewal, and support for multiple secret engines including KV, Transit (for signing/encryption), and PKI.

Built exclusively for **.NET 10** with **C# 14**, VaultaX leverages modern language features and offers a clean, fluent API that integrates naturally with ASP.NET Core and the Microsoft.Extensions ecosystem.

---

## 💖 Support the Project

VaultaX is a passion project, driven by the desire to provide a truly modern Vault integration for the .NET community. Maintaining this library requires significant effort: staying current with each .NET release, addressing issues promptly, implementing new features, keeping documentation up to date, and ensuring compatibility with HashiCorp Vault updates.

If VaultaX has helped you build better applications or saved you development time, I would be incredibly grateful for your support. Your contribution—no matter the size—helps me dedicate time to respond to issues quickly, implement improvements, and keep the library evolving alongside the .NET platform.

**I'm also looking for sponsors** who believe in this project's mission. Sponsorship helps ensure VaultaX remains actively maintained and continues to serve the .NET community for years to come.

Of course, there's absolutely no obligation. If you prefer, simply starring the repository or sharing VaultaX with fellow developers is equally appreciated!

- ⭐ **Star the repository** on GitHub to raise its visibility
- 💬 **Share** VaultaX with your team or community
- ☕ **Support via Donations:**

  - [![PayPal](https://img.shields.io/badge/PayPal-Donate-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/jorg3roch4)
  - [![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/jorg3roch4)

---

## 🎉 What's New in 1.0.0

**Initial Release!** VaultaX 1.0.0 provides a complete HashiCorp Vault integration:

- 🔐 **Transparent Configuration** - Vault secrets automatically overlay `appsettings.json`
- 🔑 **11 Authentication Methods** - Token, AppRole, Kubernetes, LDAP, JWT, AWS, Azure, and more
- 🗄️ **Secret Engines** - KV v1/v2, Transit (signing & encryption), PKI (certificates)
- 🔄 **Automatic Token Renewal** - Background service keeps tokens fresh
- 🔥 **Hot Reload** - Configuration updates without restart when secrets change
- 💚 **Health Checks** - Built-in ASP.NET Core health check integration

[See the full changelog](CHANGELOG.md) for details.

---

## 🚀 Getting Started

Integrating VaultaX into your .NET 10+ application is straightforward.

**1. Install the NuGet Package:**
```bash
dotnet add package VaultaX
```

**2. Configure appsettings.json:**
```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.example.com:8200",
    "MountPoint": "secret",
    "BasePath": "production",
    "Authentication": {
      "Method": "AppRole",
      "RoleId": "env:VAULT_ROLE_ID",
      "SecretId": "env:VAULT_SECRET_ID"
    },
    "Mappings": [
      {
        "SecretPath": "database",
        "Bindings": {
          "connectionString": "ConnectionStrings:DefaultConnection"
        }
      }
    ]
  }
}
```

**3. Register in Program.cs:**
```csharp
var builder = WebApplication.CreateBuilder(args);

// Add Vault as configuration source (secrets override appsettings)
builder.Configuration.AddVaultaX();

// Register VaultaX services
builder.Services.AddVaultaX(builder.Configuration);

// Add health checks
builder.Services.AddHealthChecks()
    .AddVaultaX();

var app = builder.Build();
app.MapHealthChecks("/health");
app.Run();
```

**4. Use Secrets Transparently:**
```csharp
public class MyService(IConfiguration configuration)
{
    // This value comes from Vault if configured, otherwise from appsettings.json
    private readonly string _connectionString = configuration.GetConnectionString("DefaultConnection");
}
```

---

## ✨ Features

### Core Capabilities
- **Transparent Configuration** - Vault secrets overlay `appsettings.json` values seamlessly
- **Environment Variables** - Use `env:VARIABLE_NAME` to read sensitive values from environment
- **Secret Mappings** - Map Vault secrets to configuration keys with flexible bindings
- **Zero Breaking Changes** - When Vault is disabled, application uses `appsettings.json` seamlessly

### Authentication Methods
- **Token** - Direct token authentication
- **AppRole** - Recommended for production workloads
- **Kubernetes** - Service account authentication for K8s pods
- **LDAP / UserPass / RADIUS** - Directory-based authentication
- **JWT / OIDC** - JSON Web Token authentication
- **AWS IAM** - AWS identity-based authentication
- **Azure Managed Identity** - Azure workload identity
- **GitHub** - GitHub token authentication
- **Certificate** - TLS client certificate authentication

### Secret Engines
- **KV v1/v2** - Key-Value secrets with `IKeyValueEngine`
- **Transit** - Encryption, decryption, and signing with `ITransitEngine`
- **PKI** - Certificate generation with `IPkiEngine`

### Enterprise Features
- **Automatic Token Renewal** - Background service renews tokens before expiration
- **Hot Reload** - React to secret changes with `IOptionsMonitor`
- **Health Checks** - Monitor Vault connectivity, seal status, and token validity
- **Custom Mount Points** - Support for non-default engine paths

---

## 🔐 Secret Engines

### Key-Value Engine

```csharp
public class SecretService(IKeyValueEngine kvEngine)
{
    public async Task<string> GetApiKeyAsync()
    {
        var secrets = await kvEngine.GetSecretAsync("api-keys");
        return secrets["apiKey"]?.ToString();
    }
}
```

### Transit Engine (Signing & Encryption)

The Transit engine keeps private keys secure in Vault:

```csharp
public class DocumentSigningService(ITransitEngine transitEngine)
{
    public async Task<string> SignDocumentAsync(byte[] documentHash)
    {
        var response = await transitEngine.SignAsync(new TransitSignRequest
        {
            KeyName = "document-signing-key",
            Input = documentHash,
            HashAlgorithm = "sha2-256",
            Prehashed = true
        });
        return response.Signature;
    }

    public async Task<string> EncryptAsync(string plaintext)
    {
        var data = Encoding.UTF8.GetBytes(plaintext);
        return await transitEngine.EncryptAsync("encryption-key", data);
    }
}
```

### PKI Engine (Certificates)

```csharp
public class CertificateService(IPkiEngine pkiEngine)
{
    public async Task<PkiCertificateResponse> IssueCertificateAsync(string commonName)
    {
        return await pkiEngine.IssueCertificateAsync(new PkiCertificateRequest
        {
            RoleName = "web-server",
            CommonName = commonName,
            Ttl = "720h"
        });
    }
}
```

---

## 📅 Versioning & .NET Support Policy

VaultaX follows a clear versioning strategy aligned with .NET's release cadence:

### Version History

| VaultaX | .NET | C# | Status |
|---------|------|-----|--------|
| **1.x** | **.NET 10** | **C# 14** | **Current** |

### Future Support Policy

VaultaX will always support the **current LTS version** plus the **next standard release**:

| VaultaX | .NET | Notes |
|---------|------|-------|
| 1.x | .NET 10 | LTS only |
| 2.x | .NET 10 + .NET 11 | LTS + Standard |
| 3.x | .NET 12 | New LTS (drops .NET 10/11) |

---

## 📚 Documentation

Comprehensive guides to help you master VaultaX:

### Getting Started
- **[Getting Started](./docs/getting-started.md)** - Installation, basic setup, and first configuration
- **[Configuration](./docs/configuration.md)** - Complete configuration reference

### Core Features
- **[Authentication](./docs/authentication.md)** - All authentication methods explained
- **[Secret Engines](./docs/secret-engines.md)** - KV, Transit, and PKI engines
- **[Signing](./docs/signing.md)** - Document signing with Transit engine

### Advanced Topics
- **[Hot Reload](./docs/hot-reload.md)** - Automatic configuration updates
- **[Health Checks](./docs/health-checks.md)** - Monitoring and health endpoints
- **[Migration](./docs/migration.md)** - Migrating from other Vault libraries
- **[Troubleshooting](./docs/troubleshooting.md)** - Common issues and solutions

### Examples
Check out the **[samples folder](./samples)** for complete working examples.

### Tools
- **[Terraform Configuration](./tools/terraform)** - Infrastructure as Code for provisioning Vault secrets

---

## 🙏 Acknowledgments

VaultaX is built on top of **[VaultSharp](https://github.com/rajanadar/VaultSharp)**, an excellent low-level Vault client for .NET. VaultaX provides a higher-level abstraction focused on configuration integration and modern .NET patterns.

**VaultSharp Project:** [VaultSharp on GitHub](https://github.com/rajanadar/VaultSharp)

---

## License

[Apache 2.0 License](LICENSE)
