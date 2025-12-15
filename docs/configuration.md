# Configuración de VaultaX

Esta guía documenta todas las opciones de configuración disponibles en VaultaX.

## Estructura de Configuración

```json
{
  "VaultaX": {
    "Enabled": true,
    "Address": "https://vault.company.com:8200",
    "MountPoint": "secret",
    "BasePath": "myapp/prod",
    "KvVersion": 2,
    "SkipCertificateValidation": false,
    "Authentication": { /* ... */ },
    "Reload": { /* ... */ },
    "TokenRenewal": { /* ... */ },
    "Mappings": [ /* ... */ ]
  }
}
```

## Opciones Principales

### `Enabled`
**Tipo:** `bool` | **Default:** `false`

Habilita o deshabilita VaultaX completamente. Cuando está deshabilitado, la aplicación usa los valores de `appsettings.json` de forma transparente.

```json
{
  "VaultaX": {
    "Enabled": true
  }
}
```

**Patrón recomendado:**
- `appsettings.Development.json`: `"Enabled": false`
- `appsettings.Production.json`: `"Enabled": true`

O mediante variable de entorno:
```bash
export VaultaX__Enabled=true
```

### `Address`
**Tipo:** `string` | **Requerido cuando `Enabled=true`**

URL del servidor Vault incluyendo protocolo y puerto.

```json
{
  "VaultaX": {
    "Address": "https://vault.company.com:8200"
  }
}
```

También puede configurarse vía variable de entorno:
```bash
export VaultaX__Address=https://vault.company.com:8200
```

### `MountPoint`
**Tipo:** `string` | **Default:** `"secret"`

Punto de montaje del secrets engine KV en Vault.

```json
{
  "VaultaX": {
    "MountPoint": "kv"
  }
}
```

**Ejemplos comunes:**
- `"secret"` - Mount point default de Vault
- `"kv"` - Nombre alternativo común
- `"myapp-secrets"` - Mount point específico de la aplicación

### `BasePath`
**Tipo:** `string` | **Default:** `""`

Ruta base dentro del secrets engine para los secretos de la aplicación.

Los secretos se buscan en: `{MountPoint}/{BasePath}/{SecretPath}`

```json
{
  "VaultaX": {
    "MountPoint": "secret",
    "BasePath": "payments/prod"
  }
}
```

Con esta configuración, un secreto `database` se busca en:
`secret/payments/prod/database`

### `KvVersion`
**Tipo:** `int` | **Default:** `2`

Versión del KV secrets engine.

| Versión | Características |
|---------|-----------------|
| 1 | Simple key-value, sin versionado |
| 2 | Versionado de secretos, metadata, soft delete |

```json
{
  "VaultaX": {
    "KvVersion": 2
  }
}
```

**Recomendación:** Usar KV v2 a menos que exista una razón específica.

### `SkipCertificateValidation`
**Tipo:** `bool` | **Default:** `false`

Omite la validación del certificado SSL de Vault.

```json
{
  "VaultaX": {
    "SkipCertificateValidation": true
  }
}
```

> **ADVERTENCIA:** Solo usar en entornos de desarrollo. NUNCA en producción.

## Autenticación (`Authentication`)

Ver [Autenticación](authentication.md) para documentación completa de todos los métodos.

### Configuración básica

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "AppRole",
      "MountPath": "auth/approle",
      "RoleId": "abc123...",
      "SecretIdEnvVar": "VAULT_SECRET_ID"
    }
  }
}
```

### Métodos soportados

| Método | Descripción | Uso principal |
|--------|-------------|---------------|
| `Token` | Token estático | Desarrollo, CI/CD |
| `AppRole` | Role ID + Secret ID | Aplicaciones, servicios |
| `Kubernetes` | Service Account | Pods en K8s |
| `Ldap` | Usuario/contraseña LDAP | Usuarios corporativos |
| `UserPass` | Usuario/contraseña local | Testing, desarrollo |
| `Jwt` | Token JWT/OIDC | SSO, federación |
| `Aws` | IAM o EC2 metadata | AWS workloads |
| `Azure` | Managed Identity | Azure workloads |
| `GitHub` | Personal Access Token | GitHub Actions |
| `Certificate` | TLS client cert | Alta seguridad |
| `Radius` | RADIUS auth | Enterprise |
| `Custom` | Auth personalizado | Casos especiales |

## Renovación de Token (`TokenRenewal`)

Configura la renovación automática del token de Vault antes de que expire.

```json
{
  "VaultaX": {
    "TokenRenewal": {
      "Enabled": true,
      "ThresholdPercent": 80,
      "CheckIntervalSeconds": 300,
      "MaxConsecutiveFailures": 3
    }
  }
}
```

### `Enabled`
**Tipo:** `bool` | **Default:** `true`

Habilita el servicio de renovación automática de token.

### `ThresholdPercent`
**Tipo:** `int` | **Default:** `80`

Porcentaje del TTL del token al cual iniciar la renovación.

Ejemplo: Token con TTL de 1 hora y threshold de 80%:
- Renovación se intenta a los ~48 minutos

### `CheckIntervalSeconds`
**Tipo:** `int` | **Default:** `300` (5 minutos)

Intervalo para verificar si se necesita renovar el token.

### `MaxConsecutiveFailures`
**Tipo:** `int` | **Default:** `3`

Número máximo de fallos consecutivos de renovación antes de intentar re-autenticación completa.

## Recarga de Secretos (`Reload`)

Configura la detección y recarga automática de cambios en secretos.

```json
{
  "VaultaX": {
    "Reload": {
      "Enabled": true,
      "IntervalSeconds": 300
    }
  }
}
```

### `Enabled`
**Tipo:** `bool` | **Default:** `false`

Habilita la verificación periódica de cambios en secretos.

### `IntervalSeconds`
**Tipo:** `int` | **Default:** `300` (5 minutos)

Intervalo en segundos para verificar cambios.

**Consideraciones:**
- Valores muy bajos aumentan carga en Vault
- Valores muy altos retrasan la propagación de cambios
- Recomendado: 300-600 segundos para producción

## Mapeos de Secretos (`Mappings`)

Define cómo los secretos de Vault se mapean a claves de configuración de .NET.

```json
{
  "VaultaX": {
    "Mappings": [
      {
        "SecretPath": "database",
        "Bindings": {
          "connectionString": "ConnectionStrings:DefaultConnection",
          "username": "Database:Username",
          "password": "Database:Password"
        }
      },
      {
        "SecretPath": "rabbitmq",
        "Bindings": {
          "host": "RabbitMQ:Host",
          "username": "RabbitMQ:Username",
          "password": "RabbitMQ:Password"
        }
      }
    ]
  }
}
```

### `SecretPath`
**Tipo:** `string`

Ruta al secreto relativa a `BasePath`.

### `Bindings`
**Tipo:** `Dictionary<string, string>`

Mapeo de claves del secreto a claves de configuración.

- **Key:** Nombre de la clave en el secreto de Vault
- **Value:** Clave en `IConfiguration`

## Ejemplo Completo

### appsettings.json (base)

```json
{
  "VaultaX": {
    "Enabled": false,
    "Address": "",
    "MountPoint": "secret",
    "BasePath": "",
    "KvVersion": 2,
    "SkipCertificateValidation": false,
    "Authentication": {
      "Method": "AppRole"
    },
    "TokenRenewal": {
      "Enabled": true,
      "ThresholdPercent": 80,
      "CheckIntervalSeconds": 300,
      "MaxConsecutiveFailures": 3
    },
    "Reload": {
      "Enabled": false,
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
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=MyApp;Integrated Security=true"
  }
}
```

### appsettings.Development.json

```json
{
  "VaultaX": {
    "Enabled": false
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=MyApp_Dev;Integrated Security=true"
  }
}
```

### appsettings.Production.json

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
    "Reload": {
      "Enabled": true,
      "IntervalSeconds": 300
    }
  }
}
```

## Configuración mediante Variables de Entorno

Todas las opciones pueden configurarse mediante variables de entorno usando el separador `__`:

```bash
# Habilitar VaultaX
export VaultaX__Enabled=true

# Dirección de Vault
export VaultaX__Address=https://vault.company.com:8200

# Base path
export VaultaX__BasePath=myapp/prod

# Método de autenticación
export VaultaX__Authentication__Method=AppRole
export VaultaX__Authentication__RoleId=abc123...

# Secretos (SIEMPRE por variable de entorno)
export VAULT_SECRET_ID=def456...
export VAULT_TOKEN=hvs.xxx...
```

## Resolución de Credenciales

Las propiedades de autenticación que terminan en `EnvVar` (como `TokenEnvVar`, `SecretIdEnvVar`, `PasswordEnvVar`) soportan tres formatos de resolución:

### 1. Variable de entorno (por defecto)

El valor se interpreta como nombre de variable de entorno:

```json
{
  "VaultaX": {
    "Authentication": {
      "TokenEnvVar": "VAULT_TOKEN"
    }
  }
}
```

```bash
export VAULT_TOKEN=hvs.CAESIJlWNGFkZjJlZjQtOGNiYy...
```

### 2. Variable de entorno explícita (`env:`)

Usa el prefijo `env:` para ser explícito sobre la fuente:

```json
{
  "VaultaX": {
    "Authentication": {
      "TokenEnvVar": "env:MY_CUSTOM_TOKEN_VAR"
    }
  }
}
```

### 3. Valor estático (`static:`)

> **⚠️ SOLO PARA DESARROLLO/TESTING**

Usa el prefijo `static:` para especificar el valor directamente:

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Token",
      "TokenEnvVar": "static:root"
    }
  }
}
```

**Casos de uso válidos para `static:`:**
- Desarrollo local con Vault en modo dev
- Pruebas unitarias e integración
- Entornos donde las variables de entorno no están disponibles (ej: WSL → Windows)

**NUNCA usar `static:` en:**
- Producción
- Ambientes QA/Staging
- Archivos que se commitean al repositorio

Ver [Autenticación - Resolución de Credenciales](authentication.md#resolución-de-credenciales) para documentación completa.

## Validación de Configuración

VaultaX valida la configuración al iniciar:

| Validación | Condición |
|------------|-----------|
| Address requerido | Si `Enabled = true`, `Address` no puede estar vacío |
| KvVersion válido | Debe ser 1 o 2 |
| Método de auth válido | Debe ser uno de los métodos soportados |
| Credenciales según método | Cada método requiere sus credenciales específicas |

Errores de validación lanzan `VaultaXConfigurationException` al iniciar la aplicación.

## Orden de Prioridad de Configuración

1. Variables de entorno (mayor prioridad)
2. Secretos de usuario (.NET User Secrets)
3. appsettings.{Environment}.json
4. appsettings.json (menor prioridad)

Los valores de Vault (cuando está habilitado) sobrescriben todos los anteriores para las claves mapeadas.

## Siguiente Paso

- [Autenticación](authentication.md) - Configuración detallada de cada método
- [Secret Engines](secret-engines.md) - KV, Transit, PKI
- [Hot Reload](hot-reload.md) - Recarga automática de secretos
