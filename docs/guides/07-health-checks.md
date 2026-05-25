# Health Checks

VaultaX incluye integración nativa con ASP.NET Core Health Checks para monitorear la conectividad con Vault.

## Configuración Básica

```csharp
var builder = WebApplication.CreateBuilder(args);

// Registrar VaultaX
builder.Services.AddVaultaX(builder.Configuration);

// Agregar Health Checks con VaultaX
builder.Services.AddHealthChecks()
    .AddVaultaX();

var app = builder.Build();

// Mapear endpoint de health check
app.MapHealthChecks("/health");

app.Run();
```

## Opciones de Configuración

```csharp
builder.Services.AddHealthChecks()
    .AddVaultaX(
        name: "vault",                          // Nombre del check
        failureStatus: HealthStatus.Degraded,   // Estado cuando falla
        tags: new[] { "ready", "live" },        // Tags para filtrado
        timeout: TimeSpan.FromSeconds(10)       // Timeout del check
    );
```

### Parámetros

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `name` | string | "vaultax" | Nombre identificador del check |
| `failureStatus` | HealthStatus? | Unhealthy | Estado reportado en fallo |
| `tags` | IEnumerable<string>? | null | Tags para filtrar checks |
| `timeout` | TimeSpan? | null | Timeout para la verificación |

## Múltiples Endpoints

### Separar Liveness y Readiness

```csharp
builder.Services.AddHealthChecks()
    .AddCheck("self", () => HealthCheckResult.Healthy(), tags: new[] { "live" })
    .AddVaultaX(name: "vault", tags: new[] { "ready" })
    .AddSqlServer(connectionString, tags: new[] { "ready" });

var app = builder.Build();

// Liveness: solo verifica que la app responde
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("live")
});

// Readiness: verifica dependencias
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});
```

### Kubernetes Probes

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: myapp
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 15
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
```

## Respuesta del Health Check

### Formato por defecto

```bash
curl http://localhost:5000/health
```

Respuesta simple:
```
Healthy
```

### Formato detallado

```csharp
app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});
```

Respuesta JSON:
```json
{
  "status": "Healthy",
  "totalDuration": "00:00:00.1234567",
  "entries": {
    "vault": {
      "status": "Healthy",
      "duration": "00:00:00.0567890",
      "description": "Vault connection is healthy",
      "data": {
        "address": "https://vault.company.com:8200",
        "authenticated": true,
        "tokenTtl": "00:45:23"
      }
    }
  }
}
```

Para usar `UIResponseWriter`, agregar el paquete:
```bash
dotnet add package AspNetCore.HealthChecks.UI.Client
```

## Datos del Health Check

El health check de VaultaX reporta:

| Campo | Descripción |
|-------|-------------|
| `address` | URL del servidor Vault |
| `authenticated` | Si está autenticado |
| `tokenTtl` | Tiempo restante del token |
| `isRenewable` | Si el token es renovable |

## Comportamiento

### Estados posibles

| Estado | Condición |
|--------|-----------|
| `Healthy` | Conectado y autenticado |
| `Degraded` | Conectado pero token expirando pronto |
| `Unhealthy` | No puede conectar o autenticar |

### Cuándo es Degraded

El check reporta `Degraded` cuando:
- Token TTL < 10% del TTL original
- La última renovación falló

### Cuándo es Unhealthy

El check reporta `Unhealthy` cuando:
- No puede conectar con Vault
- La autenticación falla
- El timeout expira

## Personalización

### Health Check personalizado

```csharp
public class CustomVaultHealthCheck : IHealthCheck
{
    private readonly Abstractions.IVaultClient _vaultClient;
    private readonly ITransitEngine _transit;

    public CustomVaultHealthCheck(
        Abstractions.IVaultClient vaultClient,
        ITransitEngine transit)
    {
        _vaultClient = vaultClient;
        _transit = transit;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken ct = default)
    {
        var data = new Dictionary<string, object>();

        try
        {
            // Verificar conexión básica
            data["authenticated"] = _vaultClient.IsAuthenticated;
            data["tokenTtl"] = _vaultClient.TokenTimeToLive?.ToString() ?? "unknown";

            // Verificar que podemos leer una llave (opcional)
            var keyInfo = await _transit.GetKeyInfoAsync("health-check-key", ct);
            data["transitKeyAvailable"] = keyInfo != null;

            return HealthCheckResult.Healthy("Vault está operacional", data);
        }
        catch (Exception ex)
        {
            data["error"] = ex.Message;
            return HealthCheckResult.Unhealthy("Error de conexión con Vault", ex, data);
        }
    }
}
```

Registro:
```csharp
builder.Services.AddHealthChecks()
    .AddCheck<CustomVaultHealthCheck>("vault-custom");
```

## Integración con Monitoreo

### Prometheus

```csharp
// Instalar: dotnet add package prometheus-net.AspNetCore.HealthChecks
builder.Services.AddHealthChecks()
    .AddVaultaX()
    .ForwardToPrometheus();

app.UseHealthChecksPrometheusExporter("/metrics");
```

Métricas expuestas:
```
# HELP healthcheck_vault_status Health check status
# TYPE healthcheck_vault_status gauge
healthcheck_vault_status{name="vault"} 1

# HELP healthcheck_vault_duration_seconds Health check duration
# TYPE healthcheck_vault_duration_seconds gauge
healthcheck_vault_duration_seconds{name="vault"} 0.057
```

### Health Check UI

```csharp
// Instalar: dotnet add package AspNetCore.HealthChecks.UI
// Instalar: dotnet add package AspNetCore.HealthChecks.UI.InMemory.Storage

builder.Services
    .AddHealthChecksUI(options =>
    {
        options.AddHealthCheckEndpoint("MyApp", "/health");
        options.SetEvaluationTimeInSeconds(30);
    })
    .AddInMemoryStorage();

var app = builder.Build();

app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapHealthChecksUI(options => options.UIPath = "/health-ui");
```

## Ejemplo Completo

### Program.cs

```csharp
using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

// Configuración
builder.Configuration.AddVaultaX();

// Servicios
builder.Services.AddVaultaX(builder.Configuration);

// Health Checks
builder.Services.AddHealthChecks()
    .AddCheck("self", () => HealthCheckResult.Healthy(), tags: new[] { "live" })
    .AddVaultaX(
        name: "vault",
        failureStatus: HealthStatus.Degraded,
        tags: new[] { "ready", "external" })
    .AddSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")!,
        name: "database",
        tags: new[] { "ready", "external" });

var app = builder.Build();

// Endpoints
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("live"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.Run();
```

### Respuesta ejemplo

```json
{
  "status": "Healthy",
  "totalDuration": "00:00:00.2345678",
  "entries": {
    "self": {
      "status": "Healthy",
      "duration": "00:00:00.0001234"
    },
    "vault": {
      "status": "Healthy",
      "duration": "00:00:00.0567890",
      "description": "Vault connection is healthy",
      "data": {
        "address": "https://vault.company.com:8200",
        "authenticated": true,
        "tokenTtl": "00:45:23",
        "isRenewable": true
      }
    },
    "database": {
      "status": "Healthy",
      "duration": "00:00:00.1776554"
    }
  }
}
```

## Siguiente Paso

- [Ejemplos](examples.md) - Casos de uso completos
- [Troubleshooting](troubleshooting.md) - Solución de problemas
