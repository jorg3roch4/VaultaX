# Inicio Rápido

Esta guía te llevará desde cero hasta tener VaultaX funcionando en tu aplicación.

## Instalación

```bash
dotnet add package VaultaX
```

## Configuración Mínima

### 1. Configurar appsettings.json

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "http://localhost:8200",
    "Authentication": {
      "Method": "Token",
      "TokenEnvVar": "VAULT_TOKEN"
    },
    "Mappings": [
      {
        "SecretPath": "database",
        "Bindings": {
          "connectionString": "ConnectionStrings:DefaultConnection"
        }
      }
    ]
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=MyDb;..."
  }
}
```

### 2. Registrar en Program.cs

```csharp
var builder = WebApplication.CreateBuilder(args);

// Paso 1: Agregar Vault como fuente de configuración
// Los secretos de Vault sobrescribirán los valores de appsettings.json
builder.Configuration.AddVaultaX();

// Paso 2: Registrar servicios de VaultaX
builder.Services.AddVaultaX(builder.Configuration);

// Paso 3 (Opcional): Agregar health check
builder.Services.AddHealthChecks()
    .AddVaultaX();

var app = builder.Build();

app.MapHealthChecks("/health");
app.Run();
```

### 3. Usar la Configuración

```csharp
public class MyService
{
    private readonly string _connectionString;

    public MyService(IConfiguration configuration)
    {
        // Este valor viene de Vault si está configurado,
        // o de appsettings.json si Vault está deshabilitado
        _connectionString = configuration.GetConnectionString("DefaultConnection")!;
    }
}
```

## Verificar que Funciona

1. Asegúrate de que Vault está corriendo:
   ```bash
   vault status
   ```

2. Exporta el token:
   ```bash
   export VAULT_TOKEN=hvs.xxx
   ```

3. Crea el secreto en Vault:
   ```bash
   vault kv put secret/database connectionString="Server=vault-server;..."
   ```

4. Ejecuta tu aplicación:
   ```bash
   dotnet run
   ```

5. Verifica el health check:
   ```bash
   curl http://localhost:5000/health
   ```

## Desarrollo Local sin Vault

Para desarrollo local sin Vault, simplemente deshabilita VaultaX:

```json
{
  "VaultaX": {
    "Enabled": false
  }
}
```

O usa una variable de entorno:
```bash
export VaultaX__Enabled=false
```

La aplicación usará los valores de `appsettings.json` de forma transparente.

## Desarrollo Local con Vault (sin variables de entorno)

Si estás desarrollando en un entorno donde las variables de entorno no funcionan correctamente (ej: WSL ejecutando procesos de Windows), puedes usar el prefijo `static:` para especificar valores directamente:

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "http://localhost:8200",
    "Authentication": {
      "Method": "Token",
      "TokenEnvVar": "static:root"
    }
  }
}
```

> **⚠️ ADVERTENCIA:** El prefijo `static:` es SOLO para desarrollo local. NUNCA usar en producción ni commitear archivos con valores estáticos de secretos.

Ver [Autenticación - Resolución de Credenciales](authentication.md#resolución-de-credenciales) para más detalles.

## Siguiente Paso

- [Configuración Completa](configuration.md) - Todas las opciones disponibles
- [Autenticación](authentication.md) - Configurar AppRole, Kubernetes, etc.
- [Firma Digital](signing.md) - Usar Transit Engine para firmar documentos
