# Troubleshooting

Esta guía cubre los problemas más comunes al usar VaultaX y sus soluciones.

## Errores de Conexión

### "Unable to connect to Vault server"

**Síntomas:**
```
VaultaXException: Unable to connect to Vault at https://vault.company.com:8200
Inner: HttpRequestException: No connection could be made because the target machine actively refused it
```

**Causas y soluciones:**

1. **Vault no está corriendo:**
   ```bash
   # Verificar estado de Vault
   vault status

   # Si usa Docker
   docker ps | grep vault
   ```

2. **URL incorrecta:**
   ```json
   {
     "VaultaX": {
       "Address": "https://vault.company.com:8200"  // Verificar protocolo y puerto
     }
   }
   ```

3. **Firewall bloqueando:**
   ```bash
   # Probar conectividad
   curl -v https://vault.company.com:8200/v1/sys/health

   # Telnet al puerto
   telnet vault.company.com 8200
   ```

4. **Certificado SSL inválido (solo desarrollo):**
   ```json
   {
     "VaultaX": {
       "SkipCertificateValidation": true  // SOLO en desarrollo
     }
   }
   ```

---

### "Certificate validation failed"

**Síntomas:**
```
HttpRequestException: The SSL connection could not be established
Inner: AuthenticationException: The remote certificate is invalid
```

**Soluciones:**

1. **Agregar CA al trust store:**
   ```bash
   # Linux
   sudo cp vault-ca.crt /usr/local/share/ca-certificates/
   sudo update-ca-certificates

   # Windows
   certutil -addstore -f "ROOT" vault-ca.crt
   ```

2. **En desarrollo, deshabilitar validación:**
   ```json
   {
     "VaultaX": {
       "SkipCertificateValidation": true
     }
   }
   ```

---

## Errores de Autenticación

### "Permission denied"

**Síntomas:**
```
VaultAuthenticationException: Failed to authenticate with Vault using AppRole: permission denied
```

**Causas y soluciones:**

1. **Role ID incorrecto:**
   ```bash
   # Verificar Role ID
   vault read auth/approle/role/myapp-role/role-id
   ```

2. **Secret ID inválido o expirado:**
   ```bash
   # Generar nuevo Secret ID
   vault write -f auth/approle/role/myapp-role/secret-id

   # Verificar que no haya expirado
   vault write auth/approle/role/myapp-role/secret-id-accessor/lookup \
       secret_id_accessor=<accessor>
   ```

3. **Mount path incorrecto:**
   ```json
   {
     "VaultaX": {
       "Authentication": {
         "Method": "AppRole",
         "MountPath": "auth/approle"  // Verificar path correcto
       }
     }
   }
   ```

4. **Variable de entorno no configurada:**
   ```bash
   # Verificar que existe
   echo $VAULT_SECRET_ID

   # Configurar
   export VAULT_SECRET_ID=your-secret-id
   ```

5. **Variables de entorno no disponibles (ej: WSL → Windows):**

   Si las variables de entorno no se propagan correctamente al proceso (común en WSL ejecutando procesos de Windows), usa el prefijo `static:` solo para desarrollo:

   ```json
   {
     "VaultaX": {
       "Authentication": {
         "Method": "Token",
         "Token": "static:root"
       }
     }
   }
   ```

   > **⚠️ ADVERTENCIA:** `static:` es SOLO para desarrollo. NUNCA en producción.

   Ver [Resolución de Credenciales](authentication.md#resolución-de-credenciales) para más detalles.

---

### "Token expired"

**Síntomas:**
```
VaultTokenExpiredException: Vault token has expired
```

**Soluciones:**

1. **Habilitar renovación automática:**
   ```json
   {
     "VaultaX": {
       "TokenRenewal": {
         "Enabled": true,
         "ThresholdPercent": 75
       }
     }
   }
   ```

2. **Verificar que el token es renovable:**
   ```bash
   vault token lookup
   # Buscar: renewable = true
   ```

3. **Aumentar TTL en Vault:**
   ```bash
   vault write auth/approle/role/myapp-role \
       token_ttl=4h \
       token_max_ttl=24h
   ```

---

### "Secret ID uses exceeded"

**Síntomas:**
```
VaultAuthenticationException: secret id has reached its usage limit
```

**Solución:**

El Secret ID tenía un límite de usos. Generar uno nuevo:

```bash
# Generar con usos ilimitados
vault write auth/approle/role/myapp-role secret_id_num_uses=0

# O específico
vault write -f auth/approle/role/myapp-role/secret-id
```

---

## Errores de Secretos

### "Secret not found"

**Síntomas:**
```
VaultSecretNotFoundException: Secret not found at path: secret/myapp/prod/database
```

**Causas y soluciones:**

1. **Path incorrecto:**
   ```bash
   # Listar secretos disponibles
   vault kv list secret/myapp/prod/

   # Verificar secreto existe
   vault kv get secret/myapp/prod/database
   ```

2. **Mount point incorrecto:**
   ```json
   {
     "VaultaX": {
       "MountPoint": "secret",  // Verificar
       "BasePath": "myapp/prod"
     }
   }
   ```

3. **KV version incorrecto:**
   ```json
   {
     "VaultaX": {
       "KvVersion": 2  // 1 o 2, según configuración de Vault
     }
   }
   ```

4. **Sin permisos de lectura:**
   ```bash
   # Verificar política
   vault policy read myapp-policy

   # Debe incluir:
   # path "secret/data/myapp/prod/*" {
   #   capabilities = ["read", "list"]
   # }
   ```

---

### "Key not found in secret"

**Síntomas:**
```
KeyNotFoundException: Key 'connectionString' not found in secret at path 'database'
```

**Solución:**

Verificar que la clave existe en el secreto:

```bash
vault kv get -format=json secret/myapp/prod/database

# Debe mostrar:
# {
#   "data": {
#     "connectionString": "Server=..."
#   }
# }
```

---

## Errores de Transit Engine

### "Key not found"

**Síntomas:**
```
VaultTransitException: Signing failed: no key found with name signing-key
```

**Solución:**

Crear la llave en Vault:

```bash
vault write -f transit/keys/signing-key type=rsa-2048
```

---

### "Invalid key type for operation"

**Síntomas:**
```
VaultTransitException: key type aes256-gcm96 does not support signing
```

**Solución:**

Usar una llave del tipo correcto:

| Operación | Tipos de llave soportados |
|-----------|---------------------------|
| Cifrado | aes128-gcm96, aes256-gcm96, chacha20-poly1305 |
| Firma | rsa-2048, rsa-3072, rsa-4096, ecdsa-p256, ecdsa-p384, ed25519 |

```bash
# Para firma, crear llave RSA o ECDSA
vault write -f transit/keys/signing-key type=rsa-2048
```

---

### "Signature verification failed"

**Síntomas:**
```
VaultTransitException: Verification failed: invalid signature
```

**Causas:**

1. **Datos modificados después de firmar**
2. **Algoritmo incorrecto:**
   ```csharp
   // Asegurarse de usar los mismos algoritmos
   var signRequest = new TransitSignRequest
   {
       KeyName = "signing-key",
       HashAlgorithm = TransitHashAlgorithm.Sha256,  // Debe coincidir
       SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15  // Debe coincidir
   };

   var verifyRequest = new TransitVerifyRequest
   {
       KeyName = "signing-key",
       HashAlgorithm = TransitHashAlgorithm.Sha256,  // Igual
       SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15  // Igual
   };
   ```

3. **Firma mal formateada:**
   ```csharp
   // La firma debe estar en formato Vault: vault:v1:base64signature
   var signature = response.Signature; // vault:v1:xxxxx

   // Si solo tienes el base64:
   var vaultSignature = $"vault:v1:{base64Signature}";
   ```

---

## Errores de Configuración

### "VaultaX configuration is invalid"

**Síntomas:**
```
VaultaXConfigurationException: VaultaX configuration is invalid: Address is required when Enabled is true
```

**Solución:**

Verificar configuración completa:

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",  // Requerido
    "Authentication": {
      "Method": "AppRole",  // Requerido
      "RoleId": "abc123",   // Requerido para AppRole
      "SecretId": "VAULT_SECRET_ID"  // Requerido para AppRole
    }
  }
}
```

---

### "Configuration key not found"

**Síntomas:**
```
Configuration key 'ConnectionStrings:DefaultConnection' not found
```

**Causas:**

1. **Mapping incorrecto:**
   ```json
   {
     "VaultaX": {
       "Mappings": [
         {
           "SecretPath": "database",
           "Bindings": {
             "connectionString": "ConnectionStrings:DefaultConnection"  // Verificar key exacta
           }
         }
       ]
     }
   }
   ```

2. **Secreto en Vault no tiene la clave esperada:**
   ```bash
   # El secreto debe tener 'connectionString' (case sensitive)
   vault kv get secret/myapp/prod/database
   ```

---

## Problemas de Rendimiento

### "Slow secret retrieval"

**Síntomas:**
- Tiempos de respuesta altos
- Timeouts frecuentes

**Soluciones:**

1. **Reducir llamadas a Vault:**
   - Usar IConfiguration con mappings (valores cacheados)
   - Evitar llamadas directas frecuentes a IKeyValueEngine

2. **Aumentar timeout:**
   ```json
   {
     "VaultaX": {
       "Timeout": 30  // segundos
     }
   }
   ```

3. **Verificar latencia de red:**
   ```bash
   curl -w "@curl-format.txt" -o /dev/null -s https://vault.company.com:8200/v1/sys/health
   ```

4. **Considerar Vault Agent:**
   - Vault Agent puede cachear localmente

---

### "Memory leak with hot reload"

**Síntomas:**
- Uso de memoria creciente
- Muchas instancias de IOptionsMonitor callbacks

**Solución:**

Deregistrar callbacks cuando el servicio se destruye:

```csharp
public class MyService : IDisposable
{
    private readonly IDisposable? _optionsChangeToken;

    public MyService(IOptionsMonitor<MySettings> options)
    {
        _optionsChangeToken = options.OnChange(OnSettingsChanged);
    }

    private void OnSettingsChanged(MySettings settings)
    {
        // Handle change
    }

    public void Dispose()
    {
        _optionsChangeToken?.Dispose();
    }
}
```

---

## Logs y Diagnóstico

### Habilitar logging detallado

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "VaultaX": "Debug",
      "VaultSharp": "Debug"
    }
  }
}
```

### Logs útiles

```
[DBG] VaultaX: Authenticating with Vault using AppRole
[INF] VaultaX: Successfully authenticated. Token TTL: 01:00:00, Renewable: True
[DBG] VaultaX: Reading secret from secret/myapp/prod/database
[DBG] VaultaX: Checking for secret changes...
[INF] VaultaX: Token renewed successfully. New TTL: 01:00:00
```

### Endpoint de diagnóstico

```csharp
app.MapGet("/debug/vault", async (
    Abstractions.IVaultClient vaultClient,
    IConfiguration config) =>
{
    return new
    {
        Authenticated = vaultClient.IsAuthenticated,
        TokenTtl = vaultClient.TokenTimeToLive?.ToString(),
        IsRenewable = vaultClient.IsTokenRenewable,
        VaultEnabled = config["VaultaX:Enabled"],
        VaultAddress = config["VaultaX:Address"]
    };
}).RequireAuthorization("Admin");
```

---

## Problemas Comunes en Kubernetes

### "ServiceAccount token not found"

**Síntomas:**
```
FileNotFoundException: /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Solución:**

Verificar que el ServiceAccount está configurado:

```yaml
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: myapp-sa  # Debe estar configurado
  automountServiceAccountToken: true  # Debe ser true
```

---

### "Kubernetes auth failed"

**Síntomas:**
```
VaultAuthenticationException: Kubernetes authentication failed: permission denied
```

**Soluciones:**

1. **Verificar role binding:**
   ```bash
   vault read auth/kubernetes/role/myapp-role
   ```

2. **Verificar service account y namespace:**
   ```yaml
   # El pod debe estar en el namespace correcto
   # con el service account correcto
   ```

3. **Verificar configuración de Kubernetes en Vault:**
   ```bash
   vault read auth/kubernetes/config
   ```

---

## Verificación de Configuración

### Script de diagnóstico

```bash
#!/bin/bash
echo "=== Vault Status ==="
vault status

echo -e "\n=== Token Info ==="
vault token lookup

echo -e "\n=== List Secrets ==="
vault kv list secret/myapp/prod/

echo -e "\n=== Test Read ==="
vault kv get secret/myapp/prod/database

echo -e "\n=== Auth Methods ==="
vault auth list

echo -e "\n=== Policies ==="
vault policy read myapp-policy
```

### Health check endpoint

```bash
curl http://localhost:5000/health/ready | jq
```

Respuesta esperada:
```json
{
  "status": "Healthy",
  "entries": {
    "vault": {
      "status": "Healthy",
      "data": {
        "authenticated": true,
        "tokenTtl": "00:45:23"
      }
    }
  }
}
```

---

## Soporte

Si el problema persiste:

1. Revisar logs de la aplicación con nivel Debug
2. Revisar logs de Vault (`vault audit`)
3. Abrir issue en GitHub con:
   - Versión de VaultaX
   - Versión de Vault
   - Configuración (sin secretos)
   - Logs relevantes
   - Pasos para reproducir

## Siguiente Paso

- [Configuración](configuration.md) - Revisar opciones
- [Ejemplos](examples.md) - Ver implementaciones correctas
