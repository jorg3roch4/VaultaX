# Autenticación con VaultaX

VaultaX soporta 12 métodos de autenticación diferentes para conectar con HashiCorp Vault.

## Métodos Disponibles

| Método | Uso Principal | Seguridad |
|--------|---------------|-----------|
| [Token](#token) | Desarrollo, CI/CD | Media |
| [AppRole](#approle) | Aplicaciones, servicios | Alta |
| [Kubernetes](#kubernetes) | Pods en Kubernetes | Alta |
| [LDAP](#ldap) | Usuarios corporativos | Media |
| [UserPass](#userpass) | Testing, desarrollo | Baja |
| [JWT/OIDC](#jwtoidc) | SSO, federación | Alta |
| [AWS](#aws) | AWS workloads | Alta |
| [Azure](#azure) | Azure workloads | Alta |
| [GitHub](#github) | GitHub Actions | Media |
| [Certificate](#certificate) | Alta seguridad | Muy Alta |
| [RADIUS](#radius) | Enterprise | Media |
| [Custom](#custom) | Casos especiales | Variable |

## Token

El método más simple. Usa un token de Vault directamente.

### Cuándo usar
- Desarrollo local
- Pipelines CI/CD con tokens temporales
- Pruebas

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Token",
      "TokenEnvVar": "VAULT_TOKEN"
    }
  }
}
```

### Variables de entorno

```bash
export VAULT_TOKEN=hvs.CAESIJlWNGFkZjJlZjQtOGNiYy...
```

### Crear token en Vault

```bash
# Token con política específica
vault token create -policy=myapp-policy -ttl=1h

# Token con role
vault token create -role=myapp-role
```

> **Nota:** Los tokens deben ser renovables para que funcione la renovación automática.

---

## AppRole

Método recomendado para aplicaciones y servicios automatizados.

### Cuándo usar
- Aplicaciones en producción
- Servicios backend
- Microservicios
- Scripts automatizados

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "AppRole",
      "MountPath": "auth/approle",
      "RoleId": "abc123-def456-...",
      "SecretIdEnvVar": "VAULT_SECRET_ID"
    }
  }
}
```

### Variables de entorno

```bash
export VAULT_SECRET_ID=xyz789-uvw012-...
```

### Configurar AppRole en Vault

```bash
# 1. Habilitar AppRole
vault auth enable approle

# 2. Crear política
vault policy write myapp-policy - <<EOF
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}
path "transit/sign/myapp-signing" {
  capabilities = ["update"]
}
EOF

# 3. Crear role
vault write auth/approle/role/myapp-role \
    token_policies="myapp-policy" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    secret_id_num_uses=0

# 4. Obtener Role ID (puede estar en config)
vault read auth/approle/role/myapp-role/role-id

# 5. Generar Secret ID (SIEMPRE en variable de entorno)
vault write -f auth/approle/role/myapp-role/secret-id
```

### Role ID vs Secret ID

| Componente | Almacenamiento | Sensibilidad |
|------------|----------------|--------------|
| Role ID | Puede estar en config | Media |
| Secret ID | SIEMPRE en env var | Alta |

---

## Kubernetes

Autenticación automática para pods en Kubernetes usando Service Accounts.

### Cuándo usar
- Aplicaciones desplegadas en Kubernetes
- Integración nativa con K8s

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Kubernetes",
      "MountPath": "auth/kubernetes",
      "KubernetesRole": "myapp-role",
      "ServiceAccountTokenPath": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    }
  }
}
```

### Configurar Kubernetes auth en Vault

```bash
# 1. Habilitar Kubernetes auth
vault auth enable kubernetes

# 2. Configurar Vault para conectar con K8s
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token

# 3. Crear role vinculado a service account
vault write auth/kubernetes/role/myapp-role \
    bound_service_account_names=myapp-sa \
    bound_service_account_namespaces=production \
    policies=myapp-policy \
    ttl=1h
```

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: production
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      serviceAccountName: myapp-sa
      containers:
      - name: myapp
        image: myapp:latest
        env:
        - name: VaultaX__Authentication__KubernetesRole
          value: "myapp-role"
```

---

## LDAP

Autenticación contra directorio LDAP/Active Directory.

### Cuándo usar
- Usuarios corporativos
- Integración con Active Directory

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Ldap",
      "MountPath": "auth/ldap",
      "Username": "serviceaccount",
      "PasswordEnvVar": "VAULT_LDAP_PASSWORD"
    }
  }
}
```

### Variables de entorno

```bash
export VAULT_LDAP_PASSWORD=SecurePassword123!
```

### Configurar LDAP en Vault

```bash
# Habilitar LDAP
vault auth enable ldap

# Configurar conexión LDAP
vault write auth/ldap/config \
    url="ldaps://ldap.company.com" \
    userattr="sAMAccountName" \
    userdn="OU=Users,DC=company,DC=com" \
    groupdn="OU=Groups,DC=company,DC=com" \
    groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" \
    groupattr="cn" \
    binddn="CN=VaultBind,OU=Service Accounts,DC=company,DC=com" \
    bindpass="BindPassword"

# Mapear grupo a política
vault write auth/ldap/groups/developers policies=developer-policy
```

---

## UserPass

Autenticación simple con usuario y contraseña.

### Cuándo usar
- Testing
- Desarrollo local
- Demos

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "UserPass",
      "MountPath": "auth/userpass",
      "Username": "devuser",
      "PasswordEnvVar": "VAULT_PASSWORD"
    }
  }
}
```

### Configurar en Vault

```bash
vault auth enable userpass

vault write auth/userpass/users/devuser \
    password="Password123" \
    policies="developer-policy"
```

---

## JWT/OIDC

Autenticación mediante tokens JWT o integración OIDC.

### Cuándo usar
- Single Sign-On (SSO)
- Federación de identidad
- GitHub Actions (OIDC)
- Google Cloud

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Jwt",
      "MountPath": "auth/jwt",
      "JwtRole": "github-actions",
      "JwtTokenEnvVar": "ACTIONS_ID_TOKEN"
    }
  }
}
```

### GitHub Actions OIDC

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    steps:
    - name: Get Vault secrets
      env:
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        ACTIONS_ID_TOKEN_REQUEST_URL: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}
      run: |
        # El token OIDC se obtiene automáticamente
        dotnet run
```

### Configurar JWT en Vault

```bash
vault auth enable jwt

# Para GitHub Actions
vault write auth/jwt/config \
    bound_issuer="https://token.actions.githubusercontent.com" \
    oidc_discovery_url="https://token.actions.githubusercontent.com"

vault write auth/jwt/role/github-actions \
    bound_audiences="https://github.com/myorg" \
    bound_subject="repo:myorg/myrepo:ref:refs/heads/main" \
    policies="ci-policy" \
    ttl=10m
```

---

## AWS

Autenticación usando credenciales AWS (IAM o EC2).

### Cuándo usar
- Aplicaciones en EC2
- Lambda functions
- ECS tasks
- EKS pods con IRSA

### Configuración IAM

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Aws",
      "MountPath": "auth/aws",
      "AwsRole": "myapp-role",
      "AwsRegion": "us-east-1",
      "AwsAuthType": "iam"
    }
  }
}
```

### Configuración EC2

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Aws",
      "AwsRole": "myapp-role",
      "AwsAuthType": "ec2"
    }
  }
}
```

### Configurar AWS auth en Vault

```bash
vault auth enable aws

# Para IAM auth
vault write auth/aws/role/myapp-role \
    auth_type=iam \
    bound_iam_principal_arn="arn:aws:iam::123456789012:role/MyAppRole" \
    policies="myapp-policy" \
    ttl=1h

# Para EC2 auth
vault write auth/aws/role/myapp-role \
    auth_type=ec2 \
    bound_ami_id="ami-12345678" \
    bound_vpc_id="vpc-abcd1234" \
    policies="myapp-policy"
```

---

## Azure

Autenticación usando Azure Managed Identity.

### Cuándo usar
- Azure VMs
- Azure App Service
- Azure Functions
- Azure Kubernetes Service (AKS)

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Azure",
      "MountPath": "auth/azure",
      "AzureRole": "myapp-role",
      "AzureResource": "https://management.azure.com/"
    }
  }
}
```

### Configurar Azure auth en Vault

```bash
vault auth enable azure

vault write auth/azure/config \
    tenant_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    resource="https://management.azure.com/"

vault write auth/azure/role/myapp-role \
    bound_subscription_ids="subscription-id" \
    bound_resource_groups="myapp-rg" \
    policies="myapp-policy"
```

---

## GitHub

Autenticación usando Personal Access Token de GitHub.

### Cuándo usar
- GitHub Actions (alternativa a OIDC)
- Desarrolladores con PAT

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "GitHub",
      "MountPath": "auth/github",
      "GitHubTokenEnvVar": "GITHUB_TOKEN"
    }
  }
}
```

### Variables de entorno

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Configurar GitHub auth en Vault

```bash
vault auth enable github

vault write auth/github/config organization="myorg"

vault write auth/github/map/teams/developers value="developer-policy"
vault write auth/github/map/users/myuser value="admin-policy"
```

---

## Certificate

Autenticación mediante certificado TLS cliente.

### Cuándo usar
- Máxima seguridad
- Comunicación machine-to-machine
- Entornos altamente regulados

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Certificate",
      "MountPath": "auth/cert",
      "CertificatePath": "/etc/ssl/client.pfx",
      "CertificatePasswordEnvVar": "CERT_PASSWORD",
      "CertificateRole": "myapp-cert"
    }
  }
}
```

### Configurar Certificate auth en Vault

```bash
vault auth enable cert

vault write auth/cert/certs/myapp-cert \
    display_name="My App" \
    policies="myapp-policy" \
    certificate=@/path/to/ca.pem \
    allowed_common_names="myapp.company.com"
```

---

## RADIUS

Autenticación contra servidor RADIUS.

### Cuándo usar
- Enterprise con infraestructura RADIUS existente

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Radius",
      "MountPath": "auth/radius",
      "RadiusUsername": "serviceuser",
      "RadiusPasswordEnvVar": "RADIUS_PASSWORD"
    }
  }
}
```

---

## Custom

Para métodos de autenticación personalizados.

### Configuración

```json
{
  "VaultaX": {
    "Authentication": {
      "Method": "Custom",
      "CustomAuthPath": "auth/custom/login",
      "CustomAuthEnvVar": "CUSTOM_AUTH_TOKEN"
    }
  }
}
```

---

## Renovación de Token

Independientemente del método de autenticación, VaultaX puede renovar automáticamente el token:

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

### Comportamiento

1. VaultaX verifica el TTL del token cada `CheckIntervalSeconds`
2. Cuando el TTL alcanza `ThresholdPercent`, intenta renovar
3. Si la renovación falla `MaxConsecutiveFailures` veces, re-autentica

### Tokens no renovables

Si el token no es renovable:
- VaultaX detecta esto automáticamente
- Intenta re-autenticación antes de expirar
- Funciona con AppRole, Kubernetes, JWT, etc.

## Resolución de Credenciales

VaultaX soporta tres formatos para especificar credenciales en las propiedades `*EnvVar`:

### 1. Variable de entorno (por defecto)

El valor se interpreta como nombre de variable de entorno:

```json
{
  "Authentication": {
    "TokenEnvVar": "VAULT_TOKEN"
  }
}
```

```bash
export VAULT_TOKEN=hvs.CAESIJlWNGFkZjJlZjQtOGNiYy...
```

### 2. Variable de entorno explícita (`env:`)

Usa el prefijo `env:` para ser explícito:

```json
{
  "Authentication": {
    "TokenEnvVar": "env:MY_CUSTOM_VAR"
  }
}
```

```bash
export MY_CUSTOM_VAR=hvs.CAESIJlWNGFkZjJlZjQtOGNiYy...
```

### 3. Valor estático (`static:`)

> **⚠️ SOLO PARA DESARROLLO/TESTING**

Usa el prefijo `static:` para especificar el valor directamente:

```json
{
  "Authentication": {
    "Method": "Token",
    "TokenEnvVar": "static:root"
  }
}
```

```json
{
  "Authentication": {
    "Method": "AppRole",
    "RoleId": "abc123-def456-...",
    "SecretIdEnvVar": "static:xyz789-uvw012-..."
  }
}
```

**Casos de uso válidos para `static:`:**
- Desarrollo local con Vault en modo dev
- Pruebas unitarias e integración
- Demostraciones y tutoriales
- Entornos donde las variables de entorno no están disponibles (ej: WSL → Windows)

**NUNCA usar `static:` en:**
- Producción
- Ambientes QA/Staging
- Archivos que se commitean al repositorio

---

## Mejores Prácticas

### 1. Nunca hardcodear secretos en producción

```json
// MAL - Nunca en producción
{
  "Authentication": {
    "SecretIdEnvVar": "static:abc123..."
  }
}

// BIEN - Usar variables de entorno
{
  "Authentication": {
    "SecretIdEnvVar": "VAULT_SECRET_ID"
  }
}
```

### 2. Usar el método más apropiado

| Entorno | Método Recomendado |
|---------|-------------------|
| Desarrollo | Token, UserPass |
| Kubernetes | Kubernetes |
| AWS | AWS IAM |
| Azure | Azure |
| CI/CD | JWT/OIDC, AppRole |
| Producción | AppRole, Kubernetes, Cloud auth |

### 3. Limitar permisos

Crear políticas con el mínimo privilegio necesario:

```hcl
# Política mínima para leer secretos
path "secret/data/myapp/*" {
  capabilities = ["read"]
}

# Si necesita firmar
path "transit/sign/myapp-key" {
  capabilities = ["update"]
}
```

### 4. TTL apropiados

| Contexto | TTL Recomendado |
|----------|-----------------|
| Desarrollo | 8h - 24h |
| CI/CD | 10m - 1h |
| Producción | 1h - 4h |

## Siguiente Paso

- [Configuración](configuration.md) - Opciones completas
- [Secret Engines](secret-engines.md) - KV, Transit, PKI
- [Firma Digital](signing.md) - Uso del Transit Engine
