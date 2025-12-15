# Ejemplos de VaultaX

Esta página contiene ejemplos prácticos de uso de VaultaX en diferentes escenarios.

## Web API con Secretos de Base de Datos

### Escenario
Una API REST que obtiene credenciales de base de datos desde Vault.

### Configuración

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "BasePath": "payments-api/prod",
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
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=dev;Trusted_Connection=true"
  }
}
```

### Código

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Vault como fuente de configuración
builder.Configuration.AddVaultaX();

// Servicios
builder.Services.AddVaultaX(builder.Configuration);
builder.Services.AddHealthChecks().AddVaultaX();

// Dapper con connection string de Vault
builder.Services.AddScoped<IDbConnection>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var connectionString = config.GetConnectionString("DefaultConnection");
    return new SqlConnection(connectionString);
});

var app = builder.Build();

app.MapHealthChecks("/health");

app.MapGet("/api/users", async (IDbConnection db) =>
{
    var users = await db.QueryAsync<User>("SELECT * FROM Users");
    return Results.Ok(users);
});

app.Run();
```

---

## Microservicio con RabbitMQ

### Escenario
Servicio que consume mensajes de RabbitMQ con credenciales de Vault.

### Configuración

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "BasePath": "consumer-service/prod",
    "Authentication": {
      "Method": "Kubernetes",
      "KubernetesRole": "consumer-service"
    },
    "Mappings": [
      {
        "SecretPath": "rabbitmq",
        "Bindings": {
          "host": "RabbitMQ:Host",
          "username": "RabbitMQ:Username",
          "password": "RabbitMQ:Password",
          "virtualHost": "RabbitMQ:VirtualHost"
        }
      }
    ]
  },
  "RabbitMQ": {
    "Host": "localhost",
    "Username": "guest",
    "Password": "guest",
    "VirtualHost": "/"
  }
}
```

### Código

```csharp
public class RabbitMQSettings
{
    public string Host { get; set; } = "localhost";
    public string Username { get; set; } = "guest";
    public string Password { get; set; } = "guest";
    public string VirtualHost { get; set; } = "/";
}

// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddVaultaX();
builder.Services.AddVaultaX(builder.Configuration);

builder.Services.Configure<RabbitMQSettings>(
    builder.Configuration.GetSection("RabbitMQ"));

builder.Services.AddSingleton<IConnection>(sp =>
{
    var settings = sp.GetRequiredService<IOptionsMonitor<RabbitMQSettings>>();
    var factory = new ConnectionFactory
    {
        HostName = settings.CurrentValue.Host,
        UserName = settings.CurrentValue.Username,
        Password = settings.CurrentValue.Password,
        VirtualHost = settings.CurrentValue.VirtualHost
    };
    return factory.CreateConnection();
});

builder.Services.AddHostedService<MessageConsumerService>();

var app = builder.Build();
app.Run();
```

---

## Firma Digital de Pagos SPEI

### Escenario
Firmar mensajes de pago SPEI según requerimientos de Banxico.

### Configuración

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "BasePath": "payments-service/prod",
    "Authentication": {
      "Method": "AppRole",
      "RoleId": "env:VAULT_ROLE_ID",
      "SecretIdEnvVar": "VAULT_SECRET_ID"
    }
  }
}
```

### Código

```csharp
public interface ISpeiSigningService
{
    Task<SpeiSignedMessage> SignMessageAsync(SpeiMessage message);
    Task<bool> VerifySignatureAsync(SpeiSignedMessage signedMessage);
}

public class SpeiSigningService : ISpeiSigningService
{
    private readonly ITransitEngine _transit;
    private readonly ILogger<SpeiSigningService> _logger;
    private const string SigningKey = "spei-banxico-key";

    public SpeiSigningService(ITransitEngine transit, ILogger<SpeiSigningService> logger)
    {
        _transit = transit;
        _logger = logger;
    }

    public async Task<SpeiSignedMessage> SignMessageAsync(SpeiMessage message)
    {
        // 1. Serializar mensaje a XML canónico
        var xmlContent = SerializeToCanonicalXml(message);
        var contentBytes = Encoding.UTF8.GetBytes(xmlContent);

        _logger.LogInformation(
            "Firmando mensaje SPEI. ClaveRastreo: {ClaveRastreo}",
            message.ClaveRastreo);

        // 2. Firmar con RSA/PKCS#1 v1.5/SHA-256 (requerido por Banxico)
        var request = new TransitSignRequest
        {
            KeyName = SigningKey,
            Data = contentBytes,
            HashAlgorithm = TransitHashAlgorithm.Sha256,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
        };

        var response = await _transit.SignAsync(request);

        // 3. Extraer firma en Base64
        var signatureBase64 = response.Signature.Split(':').Last();

        _logger.LogInformation(
            "Mensaje SPEI firmado exitosamente. ClaveRastreo: {ClaveRastreo}, KeyVersion: {KeyVersion}",
            message.ClaveRastreo, response.KeyVersion);

        return new SpeiSignedMessage
        {
            Message = message,
            XmlContent = xmlContent,
            Signature = signatureBase64,
            KeyVersion = response.KeyVersion,
            SignedAt = DateTimeOffset.UtcNow
        };
    }

    public async Task<bool> VerifySignatureAsync(SpeiSignedMessage signedMessage)
    {
        var contentBytes = Encoding.UTF8.GetBytes(signedMessage.XmlContent);
        var vaultSignature = $"vault:v{signedMessage.KeyVersion}:{signedMessage.Signature}";

        var request = new TransitVerifyRequest
        {
            KeyName = SigningKey,
            Data = contentBytes,
            Signature = vaultSignature,
            HashAlgorithm = TransitHashAlgorithm.Sha256,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
        };

        return await _transit.VerifyAsync(request);
    }

    private static string SerializeToCanonicalXml(SpeiMessage message)
    {
        // Implementar serialización XML canónica según especificación Banxico
        var settings = new XmlWriterSettings
        {
            Indent = false,
            OmitXmlDeclaration = true
        };

        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, settings);

        var serializer = new XmlSerializer(typeof(SpeiMessage));
        serializer.Serialize(xmlWriter, message);

        return stringWriter.ToString();
    }
}

public record SpeiMessage
{
    public string ClaveRastreo { get; init; } = "";
    public decimal Monto { get; init; }
    public string CuentaOrdenante { get; init; } = "";
    public string CuentaBeneficiario { get; init; } = "";
    public string ConceptoPago { get; init; } = "";
    public DateTime FechaOperacion { get; init; }
}

public record SpeiSignedMessage
{
    public required SpeiMessage Message { get; init; }
    public required string XmlContent { get; init; }
    public required string Signature { get; init; }
    public required int KeyVersion { get; init; }
    public required DateTimeOffset SignedAt { get; init; }
}
```

### Controller

```csharp
[ApiController]
[Route("api/[controller]")]
public class SpeiController : ControllerBase
{
    private readonly ISpeiSigningService _signingService;

    public SpeiController(ISpeiSigningService signingService)
    {
        _signingService = signingService;
    }

    [HttpPost("sign")]
    public async Task<ActionResult<SpeiSignedMessage>> SignMessage([FromBody] SpeiMessage message)
    {
        var signed = await _signingService.SignMessageAsync(message);
        return Ok(signed);
    }

    [HttpPost("verify")]
    public async Task<ActionResult<VerificationResult>> VerifySignature([FromBody] SpeiSignedMessage signedMessage)
    {
        var isValid = await _signingService.VerifySignatureAsync(signedMessage);
        return Ok(new VerificationResult { IsValid = isValid });
    }
}
```

---

## Cifrado de Datos Sensibles

### Escenario
Cifrar números de tarjeta de crédito antes de almacenarlos.

### Código

```csharp
public interface ICardEncryptionService
{
    Task<string> EncryptCardNumberAsync(string cardNumber);
    Task<string> DecryptCardNumberAsync(string encryptedCardNumber);
    Task<string> MigrateToNewKeyVersionAsync(string oldCiphertext);
}

public class CardEncryptionService : ICardEncryptionService
{
    private readonly ITransitEngine _transit;
    private const string EncryptionKey = "card-encryption-key";

    public CardEncryptionService(ITransitEngine transit)
    {
        _transit = transit;
    }

    public async Task<string> EncryptCardNumberAsync(string cardNumber)
    {
        // Validar formato
        if (!IsValidCardNumber(cardNumber))
            throw new ArgumentException("Número de tarjeta inválido");

        var plaintext = Encoding.UTF8.GetBytes(cardNumber);
        return await _transit.EncryptAsync(EncryptionKey, plaintext);
    }

    public async Task<string> DecryptCardNumberAsync(string encryptedCardNumber)
    {
        var plaintext = await _transit.DecryptAsync(EncryptionKey, encryptedCardNumber);
        return Encoding.UTF8.GetString(plaintext);
    }

    public async Task<string> MigrateToNewKeyVersionAsync(string oldCiphertext)
    {
        // Re-cifrar con la última versión de la llave
        return await _transit.RewrapAsync(EncryptionKey, oldCiphertext);
    }

    private static bool IsValidCardNumber(string cardNumber)
    {
        // Validación Luhn
        var sum = 0;
        var alternate = false;

        for (var i = cardNumber.Length - 1; i >= 0; i--)
        {
            if (!char.IsDigit(cardNumber[i])) continue;

            var n = cardNumber[i] - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }

        return sum % 10 == 0;
    }
}
```

---

## Emisión de Certificados TLS

### Escenario
Emitir certificados TLS para servicios internos.

### Código

```csharp
public class CertificateManager
{
    private readonly IPkiEngine _pki;
    private readonly ILogger<CertificateManager> _logger;

    public CertificateManager(IPkiEngine pki, ILogger<CertificateManager> logger)
    {
        _pki = pki;
        _logger = logger;
    }

    public async Task<X509Certificate2> GetServiceCertificateAsync(string serviceName)
    {
        _logger.LogInformation("Emitiendo certificado para servicio: {ServiceName}", serviceName);

        var request = new PkiCertificateRequest
        {
            RoleName = "internal-services",
            CommonName = $"{serviceName}.internal.company.com",
            AltNames = new[]
            {
                $"{serviceName}.default.svc.cluster.local",
                serviceName
            },
            Ttl = "720h", // 30 días
            Format = "pem"
        };

        var response = await _pki.IssueCertificateAsync(request);

        _logger.LogInformation(
            "Certificado emitido para {ServiceName}. Serial: {Serial}, Expira: {Expiration}",
            serviceName, response.SerialNumber, response.Expiration);

        // Crear X509Certificate2 desde PEM
        return X509Certificate2.CreateFromPem(response.Certificate, response.PrivateKey);
    }

    public async Task ConfigureKestrelAsync(WebApplicationBuilder builder, string serviceName)
    {
        var cert = await GetServiceCertificateAsync(serviceName);

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Any, 443, listenOptions =>
            {
                listenOptions.UseHttps(cert);
            });
        });
    }
}
```

---

## Multi-Tenant con Secretos Aislados

### Escenario
Aplicación SaaS donde cada tenant tiene sus propios secretos.

### Código

```csharp
public class TenantSecretService
{
    private readonly IKeyValueEngine _kv;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public TenantSecretService(IKeyValueEngine kv, IHttpContextAccessor httpContextAccessor)
    {
        _kv = kv;
        _httpContextAccessor = httpContextAccessor;
    }

    private string GetCurrentTenantId()
    {
        return _httpContextAccessor.HttpContext?.User
            .FindFirst("tenant_id")?.Value
            ?? throw new UnauthorizedAccessException("Tenant no identificado");
    }

    public async Task<string> GetApiKeyAsync(string serviceName)
    {
        var tenantId = GetCurrentTenantId();
        var path = $"tenants/{tenantId}/api-keys/{serviceName}";

        var secret = await _kv.ReadAsync(path);
        return secret["apiKey"]?.ToString()
            ?? throw new KeyNotFoundException($"API key no encontrada para {serviceName}");
    }

    public async Task<TenantDatabaseConfig> GetDatabaseConfigAsync()
    {
        var tenantId = GetCurrentTenantId();
        var path = $"tenants/{tenantId}/database";

        return await _kv.ReadAsync<TenantDatabaseConfig>(path);
    }
}

public class TenantDatabaseConfig
{
    public string ConnectionString { get; set; } = "";
    public string Schema { get; set; } = "dbo";
}
```

---

## Background Service con Vault

### Escenario
Servicio en background que necesita secretos de Vault.

### Código

```csharp
public class PaymentProcessorService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<PaymentProcessorService> _logger;

    public PaymentProcessorService(
        IServiceProvider serviceProvider,
        ILogger<PaymentProcessorService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();

                // Obtener servicios con secretos actualizados
                var signingService = scope.ServiceProvider
                    .GetRequiredService<ISpeiSigningService>();
                var repository = scope.ServiceProvider
                    .GetRequiredService<IPaymentRepository>();

                // Procesar pagos pendientes
                var pendingPayments = await repository.GetPendingAsync();

                foreach (var payment in pendingPayments)
                {
                    await ProcessPaymentAsync(payment, signingService, repository);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando pagos");
            }

            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }

    private async Task ProcessPaymentAsync(
        Payment payment,
        ISpeiSigningService signingService,
        IPaymentRepository repository)
    {
        var message = new SpeiMessage
        {
            ClaveRastreo = payment.TrackingId,
            Monto = payment.Amount,
            CuentaOrdenante = payment.SourceAccount,
            CuentaBeneficiario = payment.DestinationAccount,
            ConceptoPago = payment.Description,
            FechaOperacion = DateTime.UtcNow
        };

        var signedMessage = await signingService.SignMessageAsync(message);

        payment.Signature = signedMessage.Signature;
        payment.SignedAt = signedMessage.SignedAt;
        payment.Status = PaymentStatus.Signed;

        await repository.UpdateAsync(payment);

        _logger.LogInformation(
            "Pago firmado: {TrackingId}",
            payment.TrackingId);
    }
}
```

---

## Configuración Completa de Producción

### appsettings.Production.json

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "MountPoint": "secret",
    "BasePath": "payments/prod",
    "KvVersion": 2,
    "SkipCertificateValidation": false,
    "Authentication": {
      "Method": "AppRole",
      "MountPath": "auth/approle",
      "RoleId": "env:VAULT_ROLE_ID",
      "SecretIdEnvVar": "VAULT_SECRET_ID"
    },
    "TokenRenewal": {
      "Enabled": true,
      "ThresholdPercent": 75,
      "CheckIntervalSeconds": 300,
      "MaxConsecutiveFailures": 3
    },
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
      },
      {
        "SecretPath": "rabbitmq",
        "Bindings": {
          "host": "RabbitMQ:Host",
          "port": "RabbitMQ:Port",
          "username": "RabbitMQ:Username",
          "password": "RabbitMQ:Password"
        }
      },
      {
        "SecretPath": "jwt",
        "Bindings": {
          "secret": "JwtSettings:Secret",
          "issuer": "JwtSettings:Issuer"
        }
      }
    ]
  },
  "ConnectionStrings": {
    "DefaultConnection": ""
  },
  "RabbitMQ": {
    "Host": "",
    "Port": "5672",
    "Username": "",
    "Password": ""
  },
  "JwtSettings": {
    "Secret": "",
    "Issuer": "payments-api",
    "Audience": "payments-clients",
    "ExpirationMinutes": 60
  }
}
```

### Program.cs completo

```csharp
using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

// 1. Vault como fuente de configuración
builder.Configuration.AddVaultaX();

// 2. Servicios de VaultaX
builder.Services.AddVaultaX(builder.Configuration);

// 3. Health Checks
builder.Services.AddHealthChecks()
    .AddCheck("self", () => HealthCheckResult.Healthy(), tags: new[] { "live" })
    .AddVaultaX(name: "vault", tags: new[] { "ready" })
    .AddSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")!,
        name: "database",
        tags: new[] { "ready" });

// 4. Configuración tipada
builder.Services.Configure<RabbitMQSettings>(builder.Configuration.GetSection("RabbitMQ"));
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

// 5. Servicios de negocio
builder.Services.AddScoped<ISpeiSigningService, SpeiSigningService>();
builder.Services.AddScoped<ICardEncryptionService, CardEncryptionService>();

// 6. Controllers
builder.Services.AddControllers();

var app = builder.Build();

// Middleware
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// Health Checks
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = c => c.Tags.Contains("live")
});

app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = c => c.Tags.Contains("ready"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapControllers();

app.Run();
```

## Siguiente Paso

- [Migración](migration.md) - Migrar desde implementaciones existentes
- [Troubleshooting](troubleshooting.md) - Solución de problemas
