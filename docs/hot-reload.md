# Hot Reload de Secretos

VaultaX puede detectar cambios en los secretos de Vault y recargar la configuración automáticamente sin reiniciar la aplicación.

## Cómo Funciona

```
┌─────────────────────┐     ┌─────────────────────────────┐
│  Tu Aplicación      │     │     HashiCorp Vault         │
│                     │     │                             │
│  ┌───────────────┐  │     │  ┌───────────────────────┐  │
│  │ IOptions<T>   │  │     │  │ secret/myapp/database │  │
│  │ IOptionsMonitor│ │◀────│  │                       │  │
│  │ IOptionsSnapshot││     │  │ connectionString:     │  │
│  └───────────────┘  │     │  │   "Server=new..."     │  │
│         ▲           │     │  └───────────────────────┘  │
│         │           │     │             │               │
│  ┌──────┴────────┐  │     │             │               │
│  │ VaultaX       │  │     │             ▼               │
│  │ Change Watcher│──│─────│─────── Poll cada N seg ────│
│  └───────────────┘  │     │                             │
└─────────────────────┘     └─────────────────────────────┘
```

## Configuración

### Habilitar Hot Reload

```json
{
  "VaultaX": {
    "Enabled": true,
    "Reload": {
      "Enabled": true,
      "IntervalSeconds": 300
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

### Opciones de Reload

| Opción | Tipo | Default | Descripción |
|--------|------|---------|-------------|
| `Enabled` | bool | false | Habilita la verificación de cambios |
| `IntervalSeconds` | int | 300 | Intervalo de verificación en segundos |

## Uso en la Aplicación

### Con IOptionsMonitor (Recomendado)

`IOptionsMonitor<T>` se actualiza automáticamente cuando los secretos cambian:

```csharp
public class DatabaseService
{
    private readonly IOptionsMonitor<DatabaseSettings> _settings;
    private readonly ILogger<DatabaseService> _logger;

    public DatabaseService(
        IOptionsMonitor<DatabaseSettings> settings,
        ILogger<DatabaseService> logger)
    {
        _settings = settings;
        _logger = logger;

        // Registrar callback para cambios
        _settings.OnChange(OnSettingsChanged);
    }

    private void OnSettingsChanged(DatabaseSettings newSettings)
    {
        _logger.LogInformation(
            "Configuración de base de datos actualizada. Nueva conexión: {Connection}",
            MaskConnectionString(newSettings.ConnectionString));

        // Aquí puedes invalidar caches, reconectar pools, etc.
    }

    public string GetConnectionString()
    {
        // Siempre obtiene el valor más reciente
        return _settings.CurrentValue.ConnectionString;
    }

    private static string MaskConnectionString(string connStr)
    {
        // Ocultar contraseña en logs
        return Regex.Replace(connStr, @"Password=([^;]+)", "Password=***");
    }
}

public class DatabaseSettings
{
    public string ConnectionString { get; set; } = "";
}
```

### Con IOptionsSnapshot

`IOptionsSnapshot<T>` proporciona valores consistentes durante una request:

```csharp
public class PaymentController : ControllerBase
{
    private readonly IOptionsSnapshot<PaymentSettings> _settings;

    public PaymentController(IOptionsSnapshot<PaymentSettings> settings)
    {
        _settings = settings;
    }

    [HttpPost]
    public async Task<IActionResult> ProcessPayment([FromBody] PaymentRequest request)
    {
        // Los valores son consistentes durante toda la request
        var apiKey = _settings.Value.ApiKey;
        var endpoint = _settings.Value.Endpoint;

        // Si los secretos cambian durante la request, esta request
        // seguirá usando los valores originales
        await ProcessWithApiAsync(apiKey, endpoint, request);

        return Ok();
    }
}
```

### Con IConfiguration directamente

```csharp
public class ConfigAwareService
{
    private readonly IConfiguration _config;

    public ConfigAwareService(IConfiguration config)
    {
        _config = config;

        // Registrar para cambios en la configuración
        var token = _config.GetReloadToken();
        token.RegisterChangeCallback(OnConfigurationChanged, null);
    }

    private void OnConfigurationChanged(object? state)
    {
        Console.WriteLine("¡La configuración ha cambiado!");

        // Obtener el nuevo token para el próximo cambio
        var token = _config.GetReloadToken();
        token.RegisterChangeCallback(OnConfigurationChanged, null);
    }
}
```

## Ejemplo Completo

### Configuración

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "BasePath": "myapp/prod",
    "Authentication": {
      "Method": "AppRole",
      "RoleId": "abc123",
      "SecretId": "VAULT_SECRET_ID"
    },
    "Reload": {
      "Enabled": true,
      "IntervalSeconds": 60
    },
    "Mappings": [
      {
        "SecretPath": "database",
        "Bindings": {
          "connectionString": "Database:ConnectionString",
          "maxPoolSize": "Database:MaxPoolSize"
        }
      },
      {
        "SecretPath": "external-api",
        "Bindings": {
          "apiKey": "ExternalApi:ApiKey",
          "baseUrl": "ExternalApi:BaseUrl"
        }
      }
    ]
  },
  "Database": {
    "ConnectionString": "Server=fallback;Database=MyApp",
    "MaxPoolSize": "100"
  },
  "ExternalApi": {
    "ApiKey": "dev-key",
    "BaseUrl": "https://api.example.com"
  }
}
```

### Program.cs

```csharp
var builder = WebApplication.CreateBuilder(args);

// 1. Agregar Vault como fuente de configuración
builder.Configuration.AddVaultaX();

// 2. Registrar servicios de VaultaX (incluye el watcher)
builder.Services.AddVaultaX(builder.Configuration);

// 3. Registrar settings tipados
builder.Services.Configure<DatabaseSettings>(
    builder.Configuration.GetSection("Database"));
builder.Services.Configure<ExternalApiSettings>(
    builder.Configuration.GetSection("ExternalApi"));

// 4. Registrar servicios que usan IOptionsMonitor
builder.Services.AddSingleton<DatabaseService>();
builder.Services.AddScoped<ExternalApiClient>();

var app = builder.Build();
```

### Servicio con reconexión automática

```csharp
public class DatabaseConnectionManager : IDisposable
{
    private readonly IOptionsMonitor<DatabaseSettings> _settings;
    private readonly ILogger<DatabaseConnectionManager> _logger;
    private SqlConnection? _connection;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public DatabaseConnectionManager(
        IOptionsMonitor<DatabaseSettings> settings,
        ILogger<DatabaseConnectionManager> logger)
    {
        _settings = settings;
        _logger = logger;

        _settings.OnChange(async newSettings =>
        {
            await ReconnectAsync(newSettings.ConnectionString);
        });
    }

    public async Task<SqlConnection> GetConnectionAsync()
    {
        await _lock.WaitAsync();
        try
        {
            if (_connection == null || _connection.State != ConnectionState.Open)
            {
                await ReconnectAsync(_settings.CurrentValue.ConnectionString);
            }
            return _connection!;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task ReconnectAsync(string connectionString)
    {
        _logger.LogInformation("Reconectando a la base de datos...");

        var oldConnection = _connection;
        _connection = new SqlConnection(connectionString);

        try
        {
            await _connection.OpenAsync();
            _logger.LogInformation("Conexión a base de datos establecida");

            // Cerrar conexión anterior
            if (oldConnection != null)
            {
                await oldConnection.CloseAsync();
                await oldConnection.DisposeAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al conectar a la base de datos");
            _connection = oldConnection; // Restaurar conexión anterior si falla
            throw;
        }
    }

    public void Dispose()
    {
        _connection?.Dispose();
        _lock.Dispose();
    }
}
```

## Consideraciones

### Intervalo de Polling

| Intervalo | Pros | Contras |
|-----------|------|---------|
| 30-60 seg | Cambios rápidos | Mayor carga en Vault |
| 300 seg (5 min) | Balanceado | Demora aceptable |
| 600+ seg | Mínima carga | Propagación lenta |

### Detección de Cambios

VaultaX detecta cambios comparando:
- **KV v2:** Metadata de versión del secreto
- **KV v1:** Hash del contenido del secreto

### Performance

- El watcher usa un solo timer para todos los secretos mapeados
- Las verificaciones son batch para minimizar requests
- Solo se recarga si realmente hay cambios

### Limitaciones

1. **No es tiempo real:** Hay un delay hasta `IntervalSeconds`
2. **Requiere poll:** Vault no soporta push notifications nativo
3. **Un secreto = Un request:** Cada secreto mapeado genera una verificación

## Alternativas para Tiempo Real

Si necesitas actualizaciones más rápidas:

### 1. Webhook con proxy

```csharp
// Endpoint que Vault puede llamar (vía plugin o proxy)
[HttpPost("/vault-webhook")]
public IActionResult OnSecretChanged([FromBody] WebhookPayload payload)
{
    // Forzar recarga inmediata
    _configurationRoot.Reload();
    return Ok();
}
```

### 2. Vault Agent con template

```hcl
template {
  source      = "/etc/vault-agent/config.ctmpl"
  destination = "/etc/myapp/secrets.json"
  command     = "systemctl reload myapp"
}
```

### 3. Event-driven con Redis/Kafka

Publicar evento cuando cambia un secreto y suscribirse desde la aplicación.

## Debugging

### Verificar que el reload está activo

```csharp
app.MapGet("/debug/vault", (IConfiguration config) =>
{
    var reloadEnabled = config["VaultaX:Reload:Enabled"];
    var interval = config["VaultaX:Reload:IntervalSeconds"];

    return new
    {
        ReloadEnabled = reloadEnabled,
        IntervalSeconds = interval,
        LastReload = DateTimeOffset.UtcNow // En producción, trackear esto
    };
});
```

### Logs

VaultaX emite logs cuando detecta cambios:

```
[INF] VaultaX: Checking for secret changes...
[INF] VaultaX: Secret 'database' changed, reloading configuration
[INF] VaultaX: Configuration reloaded successfully
```

## Siguiente Paso

- [Health Checks](health-checks.md) - Monitoreo de salud
- [Ejemplos](examples.md) - Casos de uso completos
- [Troubleshooting](troubleshooting.md) - Solución de problemas
