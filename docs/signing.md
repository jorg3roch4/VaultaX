# Firma Digital con VaultaX

Esta guía explica cómo usar VaultaX para firmar documentos digitalmente utilizando el Transit Engine de HashiCorp Vault.

## Conceptos Clave

### ¿Por qué usar Vault para firma digital?

La firma digital tradicional requiere que la aplicación tenga acceso a la llave privada. Esto presenta varios riesgos:

1. **Exposición de llaves**: Si la aplicación es comprometida, las llaves privadas también lo son
2. **Gestión compleja**: Rotar, respaldar y auditar llaves distribuidas es difícil
3. **Cumplimiento regulatorio**: Muchas regulaciones requieren que las llaves estén en HSM o sistemas seguros

**Con Vault Transit Engine:**
- La llave privada **nunca sale de Vault**
- Vault actúa como un HSM (Hardware Security Module) en software
- Centralización de la gestión de llaves
- Auditoría completa de todas las operaciones
- Rotación de llaves sin cambiar código

```
┌─────────────────┐     ┌─────────────────────────────────────┐
│                 │     │           HashiCorp Vault           │
│  Tu Aplicación  │────▶│  ┌─────────────────────────────┐   │
│                 │     │  │     Transit Engine          │   │
│  1. Hash datos  │     │  │                             │   │
│  2. Envía hash  │────▶│  │  Llave Privada (SEGURA)    │   │
│  3. Recibe firma│◀────│  │  - Nunca exportable         │   │
│                 │     │  │  - Auditada                 │   │
└─────────────────┘     │  │  - Versionada               │   │
                        │  └─────────────────────────────┘   │
                        └─────────────────────────────────────┘
```

## Configuración Inicial

### 1. Crear una llave de firma en Vault

```bash
# Habilitar el Transit engine (si no está habilitado)
vault secrets enable transit

# Crear una llave RSA-2048 para firma
vault write -f transit/keys/document-signing type=rsa-2048

# Crear una llave RSA-4096 para mayor seguridad
vault write -f transit/keys/high-security-signing type=rsa-4096

# Crear una llave ECDSA P-256 (más eficiente)
vault write -f transit/keys/ecdsa-signing type=ecdsa-p256
```

### 2. Tipos de llaves soportados para firma

| Tipo | Descripción | Caso de uso |
|------|-------------|-------------|
| `rsa-2048` | RSA 2048 bits | Compatibilidad general, regulaciones bancarias |
| `rsa-3072` | RSA 3072 bits | Mayor seguridad, recomendado NIST |
| `rsa-4096` | RSA 4096 bits | Máxima seguridad RSA |
| `ecdsa-p256` | ECDSA curva P-256 | Eficiente, firmas pequeñas |
| `ecdsa-p384` | ECDSA curva P-384 | Balance seguridad/eficiencia |
| `ecdsa-p521` | ECDSA curva P-521 | Máxima seguridad ECDSA |
| `ed25519` | EdDSA | Más rápido, firmas pequeñas |

### 3. Configurar VaultaX en tu aplicación

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.miempresa.com:8200",
    "Authentication": {
      "Method": "AppRole",
      "RoleId": "env:VAULT_ROLE_ID",
      "SecretId": "env:VAULT_SECRET_ID"
    },
    "Transit": {
      "MountPoint": "transit",
      "DefaultSigningKey": "document-signing"
    }
  }
}
```

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddVaultaX(builder.Configuration);

var app = builder.Build();
```

## Uso Básico

### Firmar datos

```csharp
using VaultaX.Abstractions;

public class DocumentSigningService
{
    private readonly ITransitEngine _transit;

    public DocumentSigningService(ITransitEngine transit)
    {
        _transit = transit;
    }

    public async Task<string> SignDocumentAsync(byte[] documentContent)
    {
        var request = new TransitSignRequest
        {
            KeyName = "document-signing",
            Data = documentContent,
            HashAlgorithm = TransitHashAlgorithm.Sha256,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
        };

        var response = await _transit.SignAsync(request);

        // La firma está en formato: vault:v1:base64signature
        return response.Signature;
    }
}
```

### Verificar firma

```csharp
public async Task<bool> VerifySignatureAsync(byte[] documentContent, string signature)
{
    var request = new TransitVerifyRequest
    {
        KeyName = "document-signing",
        Data = documentContent,
        Signature = signature,
        HashAlgorithm = TransitHashAlgorithm.Sha256,
        SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
    };

    return await _transit.VerifyAsync(request);
}
```

## Casos de Uso Avanzados

### Firma de pagos SPEI (Banxico)

Para cumplir con los requerimientos de Banxico, los mensajes SPEI deben firmarse con RSA/PKCS#1 v1.5/SHA-256:

```csharp
public class SpeiSigningService
{
    private readonly ITransitEngine _transit;
    private const string SpeiSigningKey = "spei-signing-key";

    public SpeiSigningService(ITransitEngine transit)
    {
        _transit = transit;
    }

    /// <summary>
    /// Firma un mensaje SPEI según especificación Banxico.
    /// </summary>
    public async Task<SpeiSignedMessage> SignSpeiMessageAsync(string xmlMessage)
    {
        // 1. Convertir el mensaje a bytes (UTF-8)
        var messageBytes = Encoding.UTF8.GetBytes(xmlMessage);

        // 2. Firmar con RSA/PKCS#1 v1.5/SHA-256 (requerido por Banxico)
        var signRequest = new TransitSignRequest
        {
            KeyName = SpeiSigningKey,
            Data = messageBytes,
            HashAlgorithm = TransitHashAlgorithm.Sha256,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15  // IMPORTANTE: Banxico requiere PKCS#1 v1.5
        };

        var response = await _transit.SignAsync(signRequest);

        // 3. Extraer la firma en formato base64 (sin prefijo vault:vN:)
        var signatureBase64 = response.Signature.Split(':').Last();

        return new SpeiSignedMessage
        {
            OriginalMessage = xmlMessage,
            Signature = signatureBase64,
            KeyVersion = response.KeyVersion,
            SignedAt = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Verifica la firma de un mensaje SPEI.
    /// </summary>
    public async Task<bool> VerifySpeiSignatureAsync(string xmlMessage, string signatureBase64)
    {
        var messageBytes = Encoding.UTF8.GetBytes(xmlMessage);

        // Reconstruir el formato de firma de Vault si es necesario
        var vaultSignature = signatureBase64.StartsWith("vault:")
            ? signatureBase64
            : $"vault:v1:{signatureBase64}";

        var verifyRequest = new TransitVerifyRequest
        {
            KeyName = SpeiSigningKey,
            Data = messageBytes,
            Signature = vaultSignature,
            HashAlgorithm = TransitHashAlgorithm.Sha256,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
        };

        return await _transit.VerifyAsync(verifyRequest);
    }
}

public record SpeiSignedMessage
{
    public required string OriginalMessage { get; init; }
    public required string Signature { get; init; }
    public required int KeyVersion { get; init; }
    public required DateTimeOffset SignedAt { get; init; }
}
```

### Firma con datos pre-hasheados

Cuando ya tienes el hash del documento (útil para documentos grandes):

```csharp
public async Task<string> SignPrehashedDocumentAsync(byte[] documentHash)
{
    var request = new TransitSignRequest
    {
        KeyName = "document-signing",
        Data = documentHash,
        HashAlgorithm = TransitHashAlgorithm.Sha256,
        Prehashed = true  // Indicar que los datos ya están hasheados
    };

    var response = await _transit.SignAsync(request);
    return response.Signature;
}

// Ejemplo de uso
public async Task<string> SignLargeDocumentAsync(Stream documentStream)
{
    // 1. Calcular hash localmente (eficiente para archivos grandes)
    using var sha256 = SHA256.Create();
    var hash = await sha256.ComputeHashAsync(documentStream);

    // 2. Enviar solo el hash a Vault para firmar
    return await SignPrehashedDocumentAsync(hash);
}
```

### Firma con versión específica de llave

Útil para auditoría o cuando necesitas usar una versión anterior de la llave:

```csharp
public async Task<string> SignWithSpecificKeyVersionAsync(byte[] data, int keyVersion)
{
    var request = new TransitSignRequest
    {
        KeyName = "document-signing",
        Data = data,
        HashAlgorithm = TransitHashAlgorithm.Sha256,
        KeyVersion = keyVersion  // Usar versión específica
    };

    var response = await _transit.SignAsync(request);

    // La respuesta incluye la versión usada
    Console.WriteLine($"Firmado con versión: {response.KeyVersion}");

    return response.Signature;
}
```

### Firma ECDSA con formato JWS

Para sistemas que requieren firmas en formato JWS (JSON Web Signature):

```csharp
public async Task<string> SignForJwtAsync(byte[] payload)
{
    var request = new TransitSignRequest
    {
        KeyName = "jwt-signing-key",  // Debe ser tipo ecdsa-p256
        Data = payload,
        HashAlgorithm = TransitHashAlgorithm.Sha256,
        MarshalingAlgorithm = TransitMarshalingAlgorithm.Jws  // Formato JWS
    };

    var response = await _transit.SignAsync(request);
    return response.Signature;
}
```

## Rotación de Llaves

### Rotar una llave

```bash
# Crear una nueva versión de la llave
vault write -f transit/keys/document-signing/rotate
```

### Configurar versión mínima

```bash
# Solo permitir firmar con versión 3 o superior
vault write transit/keys/document-signing min_encryption_version=3
```

### Verificar firmas de versiones anteriores

Las firmas creadas con versiones anteriores de la llave siguen siendo verificables:

```csharp
// La firma incluye la versión: vault:v1:xxx, vault:v2:xxx, etc.
// VaultaX maneja esto automáticamente
var isValid = await _transit.VerifyAsync(new TransitVerifyRequest
{
    KeyName = "document-signing",
    Data = originalData,
    Signature = "vault:v1:base64signature..."  // Versión 1
});
```

## Obtener información de la llave

```csharp
public async Task<TransitKeyInfo?> GetSigningKeyInfoAsync()
{
    var keyInfo = await _transit.GetKeyInfoAsync("document-signing");

    if (keyInfo != null)
    {
        Console.WriteLine($"Llave: {keyInfo.Name}");
        Console.WriteLine($"Tipo: {keyInfo.Type}");
        Console.WriteLine($"Versión actual: {keyInfo.LatestVersion}");
        Console.WriteLine($"Versión mínima para firmar: {keyInfo.MinEncryptionVersion}");
        Console.WriteLine($"Exportable: {keyInfo.Exportable}");
    }

    return keyInfo;
}
```

## Algoritmos de Hash

| Algoritmo | Uso recomendado |
|-----------|-----------------|
| `Sha256` | **Recomendado para mayoría de casos** |
| `Sha384` | Mayor seguridad, compatible con P-384 |
| `Sha512` | Máxima seguridad |
| `Sha1` | **NO USAR** - Solo compatibilidad legacy |
| `Sha224` | Casos especiales |

```csharp
// Ejemplo con SHA-512
var request = new TransitSignRequest
{
    KeyName = "high-security-signing",
    Data = documentBytes,
    HashAlgorithm = TransitHashAlgorithm.Sha512
};
```

## Algoritmos de Firma RSA

| Algoritmo | Descripción | Cuándo usar |
|-----------|-------------|-------------|
| `Pss` | RSA-PSS (Probabilistic Signature Scheme) | **Recomendado** - Más seguro |
| `Pkcs1v15` | RSASSA-PKCS1-v1_5 | Compatibilidad con sistemas legacy, **requerido por Banxico** |

```csharp
// RSA-PSS (recomendado para nuevos sistemas)
var request = new TransitSignRequest
{
    KeyName = "modern-signing",
    Data = data,
    SignatureAlgorithm = TransitSignatureAlgorithm.Pss
};

// PKCS#1 v1.5 (compatibilidad/regulación)
var legacyRequest = new TransitSignRequest
{
    KeyName = "legacy-signing",
    Data = data,
    SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
};
```

## Formato de Firma

Las firmas de Vault tienen el formato: `vault:vN:base64_signature`

- `vault:` - Prefijo indicando que es una firma de Vault
- `vN` - Versión de la llave usada (v1, v2, etc.)
- `base64_signature` - La firma en Base64

### Extraer firma raw

```csharp
var response = await _transit.SignAsync(request);

// Obtener bytes de la firma (sin prefijo)
byte[] signatureBytes = response.GetSignatureBytes();

// O manualmente
string base64Only = response.Signature.Split(':')[2];
byte[] rawSignature = Convert.FromBase64String(base64Only);
```

## Ejemplo Completo: Servicio de Firma de Documentos

```csharp
using System.Security.Cryptography;
using System.Text;
using VaultaX.Abstractions;

public interface IDocumentSigningService
{
    Task<SignedDocument> SignDocumentAsync(byte[] content, string documentId);
    Task<bool> VerifyDocumentAsync(SignedDocument document);
    Task<SignedDocument> SignDocumentStreamAsync(Stream content, string documentId);
}

public class DocumentSigningService : IDocumentSigningService
{
    private readonly ITransitEngine _transit;
    private readonly ILogger<DocumentSigningService> _logger;
    private const string SigningKeyName = "document-signing";

    public DocumentSigningService(
        ITransitEngine transit,
        ILogger<DocumentSigningService> logger)
    {
        _transit = transit;
        _logger = logger;
    }

    public async Task<SignedDocument> SignDocumentAsync(byte[] content, string documentId)
    {
        _logger.LogInformation("Firmando documento {DocumentId}, tamaño: {Size} bytes",
            documentId, content.Length);

        var request = new TransitSignRequest
        {
            KeyName = SigningKeyName,
            Data = content,
            HashAlgorithm = TransitHashAlgorithm.Sha256,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
        };

        var response = await _transit.SignAsync(request);

        _logger.LogInformation(
            "Documento {DocumentId} firmado exitosamente con versión de llave {KeyVersion}",
            documentId, response.KeyVersion);

        return new SignedDocument
        {
            DocumentId = documentId,
            Content = content,
            Signature = response.Signature,
            KeyVersion = response.KeyVersion,
            SignedAt = DateTimeOffset.UtcNow,
            HashAlgorithm = "SHA256",
            SignatureAlgorithm = "RSA-PKCS1-v1_5"
        };
    }

    public async Task<SignedDocument> SignDocumentStreamAsync(Stream content, string documentId)
    {
        _logger.LogInformation("Firmando documento {DocumentId} desde stream", documentId);

        // Para documentos grandes, calcular hash localmente
        using var sha256 = SHA256.Create();
        var hash = await sha256.ComputeHashAsync(content);

        var request = new TransitSignRequest
        {
            KeyName = SigningKeyName,
            Data = hash,
            HashAlgorithm = TransitHashAlgorithm.Sha256,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15,
            Prehashed = true  // Datos ya hasheados
        };

        var response = await _transit.SignAsync(request);

        // Leer contenido para incluir en respuesta
        content.Position = 0;
        using var ms = new MemoryStream();
        await content.CopyToAsync(ms);

        return new SignedDocument
        {
            DocumentId = documentId,
            Content = ms.ToArray(),
            Signature = response.Signature,
            KeyVersion = response.KeyVersion,
            SignedAt = DateTimeOffset.UtcNow,
            HashAlgorithm = "SHA256",
            SignatureAlgorithm = "RSA-PKCS1-v1_5"
        };
    }

    public async Task<bool> VerifyDocumentAsync(SignedDocument document)
    {
        _logger.LogInformation("Verificando firma del documento {DocumentId}", document.DocumentId);

        var request = new TransitVerifyRequest
        {
            KeyName = SigningKeyName,
            Data = document.Content,
            Signature = document.Signature,
            HashAlgorithm = TransitHashAlgorithm.Sha256,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15
        };

        var isValid = await _transit.VerifyAsync(request);

        _logger.LogInformation(
            "Verificación de documento {DocumentId}: {Result}",
            document.DocumentId, isValid ? "VÁLIDA" : "INVÁLIDA");

        return isValid;
    }
}

public record SignedDocument
{
    public required string DocumentId { get; init; }
    public required byte[] Content { get; init; }
    public required string Signature { get; init; }
    public required int KeyVersion { get; init; }
    public required DateTimeOffset SignedAt { get; init; }
    public required string HashAlgorithm { get; init; }
    public required string SignatureAlgorithm { get; init; }
}
```

### Registro del servicio

```csharp
// Program.cs
builder.Services.AddVaultaX(builder.Configuration);
builder.Services.AddScoped<IDocumentSigningService, DocumentSigningService>();
```

### Uso en un controlador

```csharp
[ApiController]
[Route("api/[controller]")]
public class DocumentsController : ControllerBase
{
    private readonly IDocumentSigningService _signingService;

    public DocumentsController(IDocumentSigningService signingService)
    {
        _signingService = signingService;
    }

    [HttpPost("sign")]
    public async Task<ActionResult<SignedDocumentResponse>> SignDocument(
        IFormFile file)
    {
        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);

        var signed = await _signingService.SignDocumentAsync(
            ms.ToArray(),
            Guid.NewGuid().ToString());

        return Ok(new SignedDocumentResponse
        {
            DocumentId = signed.DocumentId,
            Signature = signed.Signature,
            SignedAt = signed.SignedAt
        });
    }

    [HttpPost("verify")]
    public async Task<ActionResult<VerificationResponse>> VerifyDocument(
        [FromBody] VerifyDocumentRequest request)
    {
        var document = new SignedDocument
        {
            DocumentId = request.DocumentId,
            Content = Convert.FromBase64String(request.ContentBase64),
            Signature = request.Signature,
            KeyVersion = 0,
            SignedAt = DateTimeOffset.MinValue,
            HashAlgorithm = "SHA256",
            SignatureAlgorithm = "RSA-PKCS1-v1_5"
        };

        var isValid = await _signingService.VerifyDocumentAsync(document);

        return Ok(new VerificationResponse
        {
            IsValid = isValid,
            VerifiedAt = DateTimeOffset.UtcNow
        });
    }
}
```

## Mejores Prácticas

### 1. Nunca exponer las llaves

```bash
# Asegurarse de que las llaves NO sean exportables
vault write transit/keys/document-signing exportable=false
```

### 2. Usar políticas restrictivas

```hcl
# policy.hcl
path "transit/sign/document-signing" {
  capabilities = ["update"]
}

path "transit/verify/document-signing" {
  capabilities = ["update"]
}

# NO dar acceso a:
# - transit/keys/* (lectura de llaves)
# - transit/export/* (exportación)
```

### 3. Auditar todas las operaciones

```bash
# Habilitar auditoría
vault audit enable file file_path=/var/log/vault/audit.log
```

### 4. Rotar llaves periódicamente

```bash
# Rotar cada 90 días (configurar con cron o similar)
vault write -f transit/keys/document-signing/rotate
```

### 5. Usar versiones mínimas

```bash
# Después de un período de gracia, aumentar versión mínima
vault write transit/keys/document-signing min_encryption_version=2
```

## Manejo de Errores

```csharp
public async Task<SignResult> SafeSignAsync(byte[] data)
{
    try
    {
        var response = await _transit.SignAsync(new TransitSignRequest
        {
            KeyName = "document-signing",
            Data = data,
            HashAlgorithm = TransitHashAlgorithm.Sha256
        });

        return SignResult.Success(response.Signature);
    }
    catch (VaultTransitException ex)
    {
        _logger.LogError(ex,
            "Error de firma Transit: Operación={Operation}, Llave={KeyName}",
            ex.Operation, ex.KeyName);

        return SignResult.Failure($"Error al firmar: {ex.Message}");
    }
    catch (VaultAuthenticationException ex)
    {
        _logger.LogError(ex, "Error de autenticación con Vault");
        return SignResult.Failure("Error de autenticación con el servicio de firma");
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error inesperado al firmar");
        return SignResult.Failure("Error inesperado");
    }
}

public record SignResult
{
    public bool IsSuccess { get; init; }
    public string? Signature { get; init; }
    public string? Error { get; init; }

    public static SignResult Success(string signature) =>
        new() { IsSuccess = true, Signature = signature };

    public static SignResult Failure(string error) =>
        new() { IsSuccess = false, Error = error };
}
```

## Troubleshooting

### Error: "key not found"

```
La llave no existe. Crearla con:
vault write -f transit/keys/nombre-llave type=rsa-2048
```

### Error: "permission denied"

```
El token/rol no tiene permisos. Verificar política:
vault policy read nombre-politica
```

### Error: "signature verification failed"

Posibles causas:
1. Los datos fueron modificados después de firmar
2. Se está usando una llave diferente
3. El algoritmo de hash/firma no coincide

### Firma muy lenta

Para documentos grandes, usar `Prehashed = true`:
```csharp
// Calcular hash localmente
var hash = SHA256.HashData(largeDocument);

// Enviar solo el hash a Vault
var request = new TransitSignRequest
{
    Data = hash,
    Prehashed = true,
    // ...
};
```

## Siguiente Paso

- [Configuración Completa](configuration.md) - Todas las opciones
- [Secret Engines](secret-engines.md) - Otros engines disponibles
- [Ejemplos](examples.md) - Más casos de uso
