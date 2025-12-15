# Migración a VaultaX

Esta guía explica cómo migrar desde diferentes implementaciones existentes hacia VaultaX.

## Desde Configuración en appsettings.json

### Antes

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=prod-db;Database=MyApp;User Id=app;Password=SuperSecret123!"
  },
  "ApiKeys": {
    "Stripe": "sk_live_xxxxx",
    "SendGrid": "SG.xxxxx"
  }
}
```

### Después

**1. Crear secretos en Vault:**

```bash
# Crear secretos
vault kv put secret/myapp/prod/database \
    connectionString="Server=prod-db;Database=MyApp;User Id=app;Password=SuperSecret123!"

vault kv put secret/myapp/prod/api-keys \
    stripe="sk_live_xxxxx" \
    sendgrid="SG.xxxxx"
```

**2. Actualizar appsettings.json:**

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "BasePath": "myapp/prod",
    "Authentication": {
      "Method": "AppRole",
      "RoleId": "env:VAULT_ROLE_ID",
      "SecretIdEnvVar": "VAULT_SECRET_ID"
    },
    "Mappings": [
      {
        "SecretPath": "database",
        "Bindings": {
          "connectionString": "ConnectionStrings:DefaultConnection"
        }
      },
      {
        "SecretPath": "api-keys",
        "Bindings": {
          "stripe": "ApiKeys:Stripe",
          "sendgrid": "ApiKeys:SendGrid"
        }
      }
    ]
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=MyApp_Dev;Trusted_Connection=true"
  },
  "ApiKeys": {
    "Stripe": "sk_test_xxxxx",
    "SendGrid": "SG.test_xxxxx"
  }
}
```

**3. Actualizar Program.cs:**

```csharp
var builder = WebApplication.CreateBuilder(args);

// Agregar VaultaX ANTES de otros servicios que usen configuración
builder.Configuration.AddVaultaX();

builder.Services.AddVaultaX(builder.Configuration);

// El resto del código no cambia
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
// En dev: usa valor de appsettings
// En prod con Vault: usa valor de Vault
```

### Ventajas
- El código existente no requiere cambios
- Valores de desarrollo siguen en appsettings
- Secretos de producción están seguros en Vault
- Transición gradual posible

---

## Desde Azure Key Vault

### Antes (con Azure.Extensions.AspNetCore.Configuration.Secrets)

```csharp
builder.Configuration.AddAzureKeyVault(
    new Uri("https://my-keyvault.vault.azure.net/"),
    new DefaultAzureCredential());
```

### Después

**1. Migrar secretos de Azure KV a HashiCorp Vault:**

```bash
# Script de migración
az keyvault secret list --vault-name my-keyvault --query "[].name" -o tsv | while read secret; do
    value=$(az keyvault secret show --vault-name my-keyvault --name "$secret" --query "value" -o tsv)
    vault kv put "secret/myapp/prod/$secret" value="$value"
done
```

**2. Actualizar código:**

```csharp
// Antes
builder.Configuration.AddAzureKeyVault(/* ... */);

// Después
builder.Configuration.AddVaultaX();
builder.Services.AddVaultaX(builder.Configuration);
```

### Mapeo de convenciones

| Azure Key Vault | HashiCorp Vault + VaultaX |
|-----------------|---------------------------|
| `Database--ConnectionString` | `secret/myapp/prod/database` → `ConnectionStrings:Default` |
| Flat keys con `--` | Estructura jerárquica en Vault |
| DefaultAzureCredential | AppRole, Kubernetes, etc. |

---

## Desde AWS Secrets Manager

### Antes

```csharp
builder.Configuration.AddSecretsManager(configurator: options =>
{
    options.SecretFilter = entry => entry.Name.StartsWith("myapp/");
    options.KeyGenerator = (entry, key) => key.Replace("__", ":");
});
```

### Después

**1. Migrar secretos:**

```bash
# Listar secretos de AWS
aws secretsmanager list-secrets --query "SecretList[?starts_with(Name, 'myapp/')].Name" --output text | while read secret; do
    value=$(aws secretsmanager get-secret-value --secret-id "$secret" --query SecretString --output text)
    # Extraer nombre sin prefijo
    name=$(echo $secret | sed 's|myapp/||')
    vault kv put "secret/myapp/prod/$name" @<(echo "$value")
done
```

**2. Actualizar configuración:**

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "BasePath": "myapp/prod",
    "Authentication": {
      "Method": "Aws",
      "AwsRole": "myapp-vault-role",
      "AwsAuthType": "iam"
    },
    "Mappings": [/* ... */]
  }
}
```

---

## Desde VaultSharp Directo

### Antes

```csharp
public class SecretService
{
    private readonly IVaultClient _vaultClient;

    public SecretService()
    {
        var authMethod = new AppRoleAuthMethodInfo(
            roleId: Environment.GetEnvironmentVariable("VAULT_ROLE_ID"),
            secretId: Environment.GetEnvironmentVariable("VAULT_SECRET_ID"));

        var settings = new VaultClientSettings("https://vault.company.com:8200", authMethod);
        _vaultClient = new VaultClient(settings);
    }

    public async Task<string> GetDatabaseConnectionStringAsync()
    {
        var secret = await _vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(
            path: "database",
            mountPoint: "secret");

        return secret.Data.Data["connectionString"]?.ToString() ?? "";
    }

    public async Task<string> SignDataAsync(byte[] data)
    {
        var result = await _vaultClient.V1.Secrets.Transit.SignDataAsync(
            keyName: "signing-key",
            new SignRequestOptions
            {
                Base64EncodedInput = Convert.ToBase64String(data),
                HashAlgorithm = TransitHashAlgorithm.SHA2_256
            },
            mountPoint: "transit");

        return result.Data.Signature;
    }
}
```

### Después

```csharp
// La configuración se centraliza
// appsettings.json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "Authentication": {
      "Method": "AppRole",
      "RoleId": "env:VAULT_ROLE_ID",
      "SecretIdEnvVar": "VAULT_SECRET_ID"
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

// Program.cs
builder.Configuration.AddVaultaX();
builder.Services.AddVaultaX(builder.Configuration);

// Servicio simplificado
public class SecretService
{
    private readonly IConfiguration _config;
    private readonly ITransitEngine _transit;

    public SecretService(IConfiguration config, ITransitEngine transit)
    {
        _config = config;
        _transit = transit;
    }

    public string GetDatabaseConnectionString()
    {
        // Ya está en IConfiguration gracias al mapping
        return _config.GetConnectionString("DefaultConnection")!;
    }

    public async Task<string> SignDataAsync(byte[] data)
    {
        var request = new TransitSignRequest
        {
            KeyName = "signing-key",
            Data = data,
            HashAlgorithm = TransitHashAlgorithm.Sha256
        };

        var response = await _transit.SignAsync(request);
        return response.Signature;
    }
}
```

### Ventajas de VaultaX
- Configuración declarativa en JSON
- Inyección de dependencias nativa
- No más código de inicialización manual
- Health checks integrados
- Renovación automática de tokens
- Hot reload de secretos

---

## Desde Implementación Custom de Vault

### Antes

```csharp
public class VaultService : IHostedService
{
    private readonly HttpClient _httpClient;
    private Timer? _renewalTimer;
    private string? _token;

    public VaultService(IHttpClientFactory factory)
    {
        _httpClient = factory.CreateClient();
        _httpClient.BaseAddress = new Uri("https://vault.company.com:8200");
    }

    public async Task StartAsync(CancellationToken ct)
    {
        // Login manual
        var response = await _httpClient.PostAsJsonAsync("/v1/auth/approle/login", new
        {
            role_id = Environment.GetEnvironmentVariable("VAULT_ROLE_ID"),
            secret_id = Environment.GetEnvironmentVariable("VAULT_SECRET_ID")
        });

        var result = await response.Content.ReadFromJsonAsync<VaultAuthResponse>();
        _token = result!.Auth.ClientToken;
        _httpClient.DefaultRequestHeaders.Add("X-Vault-Token", _token);

        // Timer para renovación
        _renewalTimer = new Timer(
            callback: async _ => await RenewTokenAsync(),
            state: null,
            dueTime: TimeSpan.FromMinutes(45),
            period: TimeSpan.FromMinutes(45));
    }

    private async Task RenewTokenAsync()
    {
        // Implementación manual de renovación...
    }

    public async Task<Dictionary<string, object>> GetSecretAsync(string path)
    {
        var response = await _httpClient.GetFromJsonAsync<VaultSecretResponse>($"/v1/secret/data/{path}");
        return response!.Data.Data;
    }

    // ... más métodos manuales
}
```

### Después

```csharp
// Todo esto se reemplaza por:

// appsettings.json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "Authentication": {
      "Method": "AppRole",
      "RoleId": "env:VAULT_ROLE_ID",
      "SecretIdEnvVar": "VAULT_SECRET_ID"
    },
    "TokenRenewal": {
      "Enabled": true,
      "ThresholdPercent": 75
    }
  }
}

// Program.cs
builder.Configuration.AddVaultaX();
builder.Services.AddVaultaX(builder.Configuration);

// Uso
public class MyService
{
    private readonly IKeyValueEngine _kv;

    public MyService(IKeyValueEngine kv) => _kv = kv;

    public async Task<Dictionary<string, object?>> GetSecretAsync(string path)
    {
        return (Dictionary<string, object?>)await _kv.ReadAsync(path);
    }
}
```

---

## Migración Gradual

Para proyectos grandes, se recomienda migrar gradualmente:

### Fase 1: Agregar VaultaX sin cambios

```csharp
// Program.cs
builder.Configuration.AddVaultaX(); // No hace nada si Enabled=false

builder.Services.AddVaultaX(builder.Configuration);
```

```json
{
  "VaultaX": {
    "Enabled": false
  }
}
```

### Fase 2: Migrar primer secreto

```bash
# Crear secreto en Vault
vault kv put secret/myapp/prod/database connectionString="Server=..."
```

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
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

### Fase 3: Migrar secretos adicionales

Continuar agregando mappings conforme se migran secretos.

### Fase 4: Eliminar secretos de appsettings

Una vez validado que todo funciona, eliminar valores sensibles de appsettings.json:

```json
{
  "VaultaX": {
    "Enabled": true,
    "Mappings": [/* ... */]
  },
  "ConnectionStrings": {
    "DefaultConnection": "" // Vacío, viene de Vault
  }
}
```

---

## Checklist de Migración

- [ ] Instalar VaultaX: `dotnet add package VaultaX`
- [ ] Agregar `builder.Configuration.AddVaultaX()` en Program.cs
- [ ] Agregar `builder.Services.AddVaultaX(builder.Configuration)` en Program.cs
- [ ] Configurar autenticación en appsettings.json
- [ ] Crear secretos en Vault
- [ ] Agregar mappings para cada secreto
- [ ] Probar en ambiente de desarrollo
- [ ] Probar en ambiente de staging
- [ ] Desplegar en producción
- [ ] Eliminar secretos de appsettings.json
- [ ] Eliminar código legacy de acceso a secretos

## Siguiente Paso

- [Troubleshooting](troubleshooting.md) - Solución de problemas comunes
- [Ejemplos](examples.md) - Casos de uso avanzados
