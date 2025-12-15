# VaultaX Documentation

Documentación completa para VaultaX - Biblioteca .NET para integración con HashiCorp Vault.

## Contenido

1. [Inicio Rápido](getting-started.md) - Configuración básica y primer uso
2. [Configuración](configuration.md) - Todas las opciones de configuración
3. [Autenticación](authentication.md) - Métodos de autenticación soportados
4. [Secret Engines](secret-engines.md) - KV, Transit y PKI
5. [Firma Digital](signing.md) - Guía completa para firma de documentos
6. [Hot Reload](hot-reload.md) - Recarga automática de secretos
7. [Health Checks](health-checks.md) - Monitoreo de salud
8. [Ejemplos](examples.md) - Casos de uso comunes
9. [Migración](migration.md) - Migrar desde implementaciones existentes
10. [Troubleshooting](troubleshooting.md) - Solución de problemas

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                        Tu Aplicación                            │
├─────────────────────────────────────────────────────────────────┤
│  IConfiguration  │  IKeyValueEngine  │  ITransitEngine  │  ... │
├─────────────────────────────────────────────────────────────────┤
│                         VaultaX                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ Config      │  │ Secret      │  │ Background Services     │ │
│  │ Provider    │  │ Engines     │  │ - Token Renewal         │ │
│  │             │  │ - KV        │  │ - Secret Change Watcher │ │
│  │             │  │ - Transit   │  │                         │ │
│  │             │  │ - PKI       │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                       VaultSharp                                │
├─────────────────────────────────────────────────────────────────┤
│                    HashiCorp Vault                              │
└─────────────────────────────────────────────────────────────────┘
```

## Características Principales

| Característica | Descripción |
|---------------|-------------|
| Configuración Transparente | Secretos de Vault sobrescriben valores de appsettings.json |
| 12 Métodos de Auth | Token, AppRole, Kubernetes, LDAP, JWT, AWS, Azure, etc. |
| Hot Reload | Recarga automática cuando los secretos cambian |
| Token Renewal | Renovación automática de tokens antes de expirar |
| Health Checks | Integración nativa con ASP.NET Core |
| Transit Engine | Firma y cifrado sin exponer llaves privadas |
| PKI Engine | Emisión y gestión de certificados |

## Requisitos

- .NET 8.0 o superior
- HashiCorp Vault 1.12 o superior
- VaultSharp 1.17.x

## Licencia

Apache 2.0
