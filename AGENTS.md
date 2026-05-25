# VaultaX — Agent Context

## Project

HashiCorp Vault integration library for .NET 10+. Provides transparent secret management where Vault secrets automatically overlay appsettings.json values. Supports multiple auth methods, KV/Transit/PKI secret engines, automatic token renewal, and hot-reload. Built on VaultSharp. Published to NuGet.

## Solution: VaultaX.sln

### Source packages (src/)
- **VaultaX** — Single package: configuration, auth, secret engines, health checks

### Tests (tests/)
- VaultaX.Tests — Unit and integration tests

### Samples (samples/)
- VaultaX.Sample.WebApi — ASP.NET Core Web API demonstrating transparent config overlay
- VaultaX.Sample.Console — Console app demonstrating direct secret access

## Source Structure (src/VaultaX/)

- **Abstractions/** — IVaultClient, IKeyValueEngine, ITransitEngine, IPkiEngine
- **Authentication/** — Token, AppRole, Kubernetes, LDAP, JWT, AWS, Azure auth methods
- **BackgroundServices/** — Automatic token renewal background service
- **Configuration/** — IConfigurationSource/Provider, AddVaultaX(), hot-reload via IOptionsMonitor
- **Engines/** — KV v1/v2, Transit (sign/encrypt), PKI (certificates) implementations
- **Exceptions/** — VaultaX-specific exception types
- **Extensions/** — AddVaultaX() DI registration, AddVaultaX() IConfigurationBuilder
- **HealthChecks/** — ASP.NET Core health check (connection + auth status)
- **Services/** — High-level service layer on top of VaultSharp

## Stack

- .NET 10 / C# 14, nullable enabled, no implicit usings, warnings as errors, strict features
- Directory.Build.props provides shared package metadata for all projects
- Dependency: VaultSharp 1.17.5.1, Microsoft.Extensions.* 10.0.3
- v1.0.2: Eager authentication — IsAuthenticated is true immediately after DI resolution
- env:VARIABLE_NAME syntax supported in config for sensitive values
