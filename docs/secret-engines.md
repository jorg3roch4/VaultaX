# Secret Engines

VaultaX soporta tres Secret Engines de HashiCorp Vault: KV (Key-Value), Transit y PKI.

## Visión General

```
┌─────────────────────────────────────────────────────────────┐
│                      Secret Engines                          │
├─────────────────┬─────────────────┬─────────────────────────┤
│       KV        │     Transit     │          PKI            │
├─────────────────┼─────────────────┼─────────────────────────┤
│ Almacena        │ Criptografía    │ Certificados            │
│ secretos        │ como servicio   │ X.509                   │
│                 │                 │                         │
│ - Passwords     │ - Cifrado       │ - Emisión de certs      │
│ - API Keys      │ - Firma digital │ - Firma de CSR          │
│ - Connection    │ - HMAC          │ - Revocación            │
│   strings       │ - Hash          │ - CRL/OCSP              │
└─────────────────┴─────────────────┴─────────────────────────┘
```

## KV (Key-Value) Engine

El KV Engine almacena secretos arbitrarios como pares clave-valor.

### IKeyValueEngine Interface

```csharp
public interface IKeyValueEngine : ISecretEngine
{
    Task<IDictionary<string, object?>> ReadAsync(string path, int? version = null, CancellationToken ct = default);
    Task<T> ReadAsync<T>(string path, int? version = null, CancellationToken ct = default) where T : class, new();
    Task WriteAsync(string path, IDictionary<string, object?> data, int? checkAndSet = null, CancellationToken ct = default);
    Task DeleteAsync(string path, CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListAsync(string path, CancellationToken ct = default);
    Task<SecretMetadata?> GetMetadataAsync(string path, CancellationToken ct = default);
}
```

### Leer secretos

```csharp
public class DatabaseService
{
    private readonly IKeyValueEngine _kv;

    public DatabaseService(IKeyValueEngine kv)
    {
        _kv = kv;
    }

    public async Task<string> GetConnectionStringAsync()
    {
        // Leer como diccionario
        var secret = await _kv.ReadAsync("database");
        return secret["connectionString"]?.ToString() ?? "";
    }

    public async Task<DatabaseSecrets> GetDatabaseSecretsAsync()
    {
        // Leer con deserialización automática
        return await _kv.ReadAsync<DatabaseSecrets>("database");
    }
}

public class DatabaseSecrets
{
    public string ConnectionString { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}
```

### Escribir secretos

```csharp
public async Task SaveApiKeyAsync(string serviceName, string apiKey)
{
    var data = new Dictionary<string, object?>
    {
        ["apiKey"] = apiKey,
        ["createdAt"] = DateTimeOffset.UtcNow.ToString("O"),
        ["createdBy"] = "admin-service"
    };

    await _kv.WriteAsync($"api-keys/{serviceName}", data);
}
```

### Check-And-Set (CAS)

Para operaciones concurrentes seguras (solo KV v2):

```csharp
public async Task UpdateSecretSafelyAsync(string path, string newValue)
{
    // 1. Leer versión actual
    var metadata = await _kv.GetMetadataAsync(path);
    var currentVersion = metadata?.CurrentVersion ?? 0;

    // 2. Escribir solo si la versión no ha cambiado
    var data = new Dictionary<string, object?>
    {
        ["value"] = newValue
    };

    try
    {
        await _kv.WriteAsync(path, data, checkAndSet: currentVersion);
    }
    catch (VaultaXException ex) when (ex.Message.Contains("check-and-set"))
    {
        throw new ConcurrencyException("El secreto fue modificado por otro proceso");
    }
}
```

### Listar secretos

```csharp
public async Task<IReadOnlyList<string>> ListApiKeysAsync()
{
    return await _kv.ListAsync("api-keys");
}
```

### Eliminar secretos

```csharp
public async Task DeleteApiKeyAsync(string serviceName)
{
    await _kv.DeleteAsync($"api-keys/{serviceName}");
}
```

### Versiones (KV v2)

```csharp
public async Task<string> GetSecretVersionAsync(string path, int version)
{
    // Leer versión específica
    var secret = await _kv.ReadAsync(path, version: version);
    return secret["value"]?.ToString() ?? "";
}

public async Task<SecretMetadata?> GetSecretHistoryAsync(string path)
{
    var metadata = await _kv.GetMetadataAsync(path);

    Console.WriteLine($"Versión actual: {metadata?.CurrentVersion}");
    Console.WriteLine($"Versión más antigua: {metadata?.OldestVersion}");
    Console.WriteLine($"Creado: {metadata?.CreatedTime}");
    Console.WriteLine($"Actualizado: {metadata?.UpdatedTime}");

    return metadata;
}
```

---

## Transit Engine

El Transit Engine proporciona criptografía como servicio. Las llaves nunca salen de Vault.

### ITransitEngine Interface

```csharp
public interface ITransitEngine : ISecretEngine
{
    // Cifrado
    Task<string> EncryptAsync(string keyName, byte[] plaintext, byte[]? context = null, CancellationToken ct = default);
    Task<byte[]> DecryptAsync(string keyName, string ciphertext, byte[]? context = null, CancellationToken ct = default);

    // Firma digital
    Task<TransitSignResponse> SignAsync(TransitSignRequest request, CancellationToken ct = default);
    Task<bool> VerifyAsync(TransitVerifyRequest request, CancellationToken ct = default);

    // Hash y HMAC
    Task<string> HashAsync(byte[] data, TransitHashAlgorithm algorithm = TransitHashAlgorithm.Sha256, TransitOutputFormat format = TransitOutputFormat.Base64, CancellationToken ct = default);
    Task<string> HmacAsync(string keyName, byte[] data, TransitHashAlgorithm algorithm = TransitHashAlgorithm.Sha256, CancellationToken ct = default);

    // Utilidades
    Task<string> GenerateRandomBytesAsync(int byteCount, TransitOutputFormat format = TransitOutputFormat.Base64, CancellationToken ct = default);
    Task<TransitKeyInfo?> GetKeyInfoAsync(string keyName, CancellationToken ct = default);
    Task<string> RewrapAsync(string keyName, string ciphertext, byte[]? context = null, CancellationToken ct = default);
}
```

### Cifrado

```csharp
public class EncryptionService
{
    private readonly ITransitEngine _transit;

    public EncryptionService(ITransitEngine transit)
    {
        _transit = transit;
    }

    public async Task<string> EncryptSensitiveDataAsync(string data)
    {
        var plaintext = Encoding.UTF8.GetBytes(data);

        // Cifrado con llave "data-encryption"
        var ciphertext = await _transit.EncryptAsync("data-encryption", plaintext);

        // Resultado: vault:v1:base64ciphertext...
        return ciphertext;
    }

    public async Task<string> DecryptDataAsync(string ciphertext)
    {
        var plaintext = await _transit.DecryptAsync("data-encryption", ciphertext);
        return Encoding.UTF8.GetString(plaintext);
    }
}
```

### Cifrado con contexto (Derived Keys)

Para cifrado convergente donde el mismo plaintext produce el mismo ciphertext:

```csharp
public async Task<string> EncryptWithContextAsync(string data, string userId)
{
    var plaintext = Encoding.UTF8.GetBytes(data);
    var context = Encoding.UTF8.GetBytes(userId); // El contexto debe ser único por entidad

    return await _transit.EncryptAsync("convergent-key", plaintext, context);
}
```

### Firma Digital

Para documentación completa de firma, ver [Firma Digital](signing.md).

```csharp
public async Task<string> SignDataAsync(byte[] data)
{
    var request = new TransitSignRequest
    {
        KeyName = "signing-key",
        Data = data,
        HashAlgorithm = TransitHashAlgorithm.Sha256,
        SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
    };

    var response = await _transit.SignAsync(request);
    return response.Signature;
}

public async Task<bool> VerifySignatureAsync(byte[] data, string signature)
{
    var request = new TransitVerifyRequest
    {
        KeyName = "signing-key",
        Data = data,
        Signature = signature,
        HashAlgorithm = TransitHashAlgorithm.Sha256,
        SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
    };

    return await _transit.VerifyAsync(request);
}
```

### Hash

```csharp
public async Task<string> HashDataAsync(byte[] data)
{
    // SHA-256 en Base64
    var hash = await _transit.HashAsync(data, TransitHashAlgorithm.Sha256);
    return hash;
}

public async Task<string> HashAsHexAsync(byte[] data)
{
    // SHA-512 en hexadecimal
    var hash = await _transit.HashAsync(
        data,
        TransitHashAlgorithm.Sha512,
        TransitOutputFormat.Hex);
    return hash;
}
```

### HMAC

```csharp
public async Task<string> GenerateHmacAsync(byte[] data)
{
    return await _transit.HmacAsync("hmac-key", data, TransitHashAlgorithm.Sha256);
}
```

### Bytes Aleatorios

```csharp
public async Task<string> GenerateApiKeyAsync()
{
    // 32 bytes aleatorios en Base64
    var randomBytes = await _transit.GenerateRandomBytesAsync(32);
    return randomBytes;
}

public async Task<string> GenerateHexTokenAsync()
{
    // 16 bytes aleatorios en hexadecimal
    var token = await _transit.GenerateRandomBytesAsync(16, TransitOutputFormat.Hex);
    return token;
}
```

### Información de Llave

```csharp
public async Task DisplayKeyInfoAsync(string keyName)
{
    var info = await _transit.GetKeyInfoAsync(keyName);

    if (info != null)
    {
        Console.WriteLine($"Nombre: {info.Name}");
        Console.WriteLine($"Tipo: {info.Type}");
        Console.WriteLine($"Versión actual: {info.LatestVersion}");
        Console.WriteLine($"Min versión cifrado: {info.MinEncryptionVersion}");
        Console.WriteLine($"Min versión descifrado: {info.MinDecryptionVersion}");
        Console.WriteLine($"Exportable: {info.Exportable}");
    }
}
```

### Re-wrap (Rotación de Llaves)

Cuando se rota una llave, se puede re-cifrar datos existentes con la nueva versión:

```csharp
public async Task<string> UpgradeCiphertextAsync(string oldCiphertext)
{
    // Re-cifra con la última versión de la llave
    return await _transit.RewrapAsync("data-encryption", oldCiphertext);
}
```

### Crear llaves en Vault

```bash
# Llave para cifrado
vault write -f transit/keys/data-encryption type=aes256-gcm96

# Llave para firma RSA
vault write -f transit/keys/signing-key type=rsa-2048

# Llave para firma ECDSA
vault write -f transit/keys/ecdsa-key type=ecdsa-p256

# Llave para HMAC
vault write -f transit/keys/hmac-key type=aes256-gcm96

# Llave convergente (para búsquedas)
vault write -f transit/keys/convergent-key type=aes256-gcm96 derived=true convergent_encryption=true
```

---

## PKI Engine

El PKI Engine emite y gestiona certificados X.509.

### IPkiEngine Interface

```csharp
public interface IPkiEngine : ISecretEngine
{
    Task<PkiCertificateResponse> IssueCertificateAsync(PkiCertificateRequest request, CancellationToken ct = default);
    Task<PkiCertificateResponse> SignCsrAsync(string roleName, string csr, string commonName, string? ttl = null, CancellationToken ct = default);
    Task RevokeCertificateAsync(string serialNumber, CancellationToken ct = default);
    Task<string> GetCaCertificateAsync(string format = "pem", CancellationToken ct = default);
    Task<string> GetCertificateChainAsync(CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListCertificatesAsync(CancellationToken ct = default);
}
```

### Emitir Certificado

```csharp
public class CertificateService
{
    private readonly IPkiEngine _pki;

    public CertificateService(IPkiEngine pki)
    {
        _pki = pki;
    }

    public async Task<PkiCertificateResponse> IssueCertificateAsync(string hostname)
    {
        var request = new PkiCertificateRequest
        {
            RoleName = "web-server",
            CommonName = hostname,
            AltNames = new[] { $"www.{hostname}" },
            Ttl = "720h", // 30 días
            Format = "pem"
        };

        return await _pki.IssueCertificateAsync(request);
    }
}
```

### Usar el certificado

```csharp
public async Task ConfigureKestrelAsync(PkiCertificateResponse cert)
{
    // Combinar certificado y llave privada
    var certPem = cert.Certificate;
    var keyPem = cert.PrivateKey!;

    // Crear X509Certificate2
    var certificate = X509Certificate2.CreateFromPem(certPem, keyPem);

    // Usar en Kestrel
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.Listen(IPAddress.Any, 443, listenOptions =>
        {
            listenOptions.UseHttps(certificate);
        });
    });
}
```

### Firmar CSR

```csharp
public async Task<string> SignCsrAsync(string csrPem)
{
    var response = await _pki.SignCsrAsync(
        roleName: "internal-server",
        csr: csrPem,
        commonName: "app.internal.company.com",
        ttl: "8760h" // 1 año
    );

    return response.Certificate;
}
```

### Obtener CA

```csharp
public async Task<string> GetCaCertificateAsync()
{
    // En formato PEM
    return await _pki.GetCaCertificateAsync("pem");
}

public async Task<string> GetFullChainAsync()
{
    return await _pki.GetCertificateChainAsync();
}
```

### Revocar Certificado

```csharp
public async Task RevokeCertificateAsync(string serialNumber)
{
    await _pki.RevokeCertificateAsync(serialNumber);
    Console.WriteLine($"Certificado {serialNumber} revocado");
}
```

### Listar Certificados

```csharp
public async Task<IReadOnlyList<string>> ListCertificatesAsync()
{
    return await _pki.ListCertificatesAsync();
}
```

### Configurar PKI en Vault

```bash
# 1. Habilitar PKI
vault secrets enable pki

# 2. Configurar TTL máximo
vault secrets tune -max-lease-ttl=87600h pki

# 3. Generar CA raíz
vault write pki/root/generate/internal \
    common_name="Company Root CA" \
    ttl=87600h

# 4. Configurar URLs
vault write pki/config/urls \
    issuing_certificates="https://vault.company.com:8200/v1/pki/ca" \
    crl_distribution_points="https://vault.company.com:8200/v1/pki/crl"

# 5. Crear role
vault write pki/roles/web-server \
    allowed_domains="company.com" \
    allow_subdomains=true \
    max_ttl="720h"
```

---

## Registro de Servicios

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Registrar VaultaX (incluye todos los engines)
builder.Services.AddVaultaX(builder.Configuration);

// Los engines se inyectan automáticamente
var app = builder.Build();
```

### Uso en Servicios

```csharp
public class MyService
{
    private readonly IKeyValueEngine _kv;
    private readonly ITransitEngine _transit;
    private readonly IPkiEngine _pki;

    public MyService(
        IKeyValueEngine kv,
        ITransitEngine transit,
        IPkiEngine pki)
    {
        _kv = kv;
        _transit = transit;
        _pki = pki;
    }
}
```

## Siguiente Paso

- [Firma Digital](signing.md) - Guía completa de Transit para firma
- [Ejemplos](examples.md) - Casos de uso prácticos
- [Hot Reload](hot-reload.md) - Recarga automática de secretos
