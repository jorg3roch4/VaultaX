# Changelog

All notable changes to VaultaX will be documented in this file.

## [1.0.1] - 2025-12-16

### Changed
- **Fluent API and AppSettings Synchronization** - All authentication properties are now fully synchronized between both configuration approaches with identical names.
- **Simplified Authentication Property Names** - Unified contextual properties (`Role`, `Token`, `Username`, `Password`) and shorter names across all authentication methods.

### Fixed
- **Health Check Extension** - Now gracefully handles disabled VaultaX by returning healthy status.

### Updated
- Documentation and samples updated

## [1.0.0] - 2025-12-15

### Added
- Initial release
- **Configuration Integration**
  - Transparent overlay of Vault secrets on `appsettings.json`
  - Hot reload support with `IOptionsMonitor`
  - Environment variable resolution (`env:VARIABLE_NAME`)
- **Authentication Methods**
  - Token authentication
  - AppRole (recommended for production)
  - Kubernetes service account
  - LDAP / UserPass / RADIUS
  - JWT / OIDC
  - AWS IAM
  - Azure Managed Identity
  - GitHub
  - Certificate (TLS)
- **Secret Engines**
  - KV v1/v2 with `IKeyValueEngine`
  - Transit (signing & encryption) with `ITransitEngine`
  - PKI (certificates) with `IPkiEngine`
- **Token Management**
  - Automatic token renewal background service
  - Configurable renewal threshold and check interval
  - Failure handling with max consecutive failures
- **Health Checks**
  - ASP.NET Core health check integration
  - Vault connectivity verification
  - Seal status monitoring
  - Token expiration warnings
- **Developer Experience**
  - Fluent configuration API
  - Secret path mappings with bindings
  - Custom mount point support
  - Graceful fallback when Vault is disabled

### Packages
- `VaultaX` - Complete HashiCorp Vault integration for .NET 10+
