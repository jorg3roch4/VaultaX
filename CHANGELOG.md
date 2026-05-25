# Changelog

All notable changes to VaultaX will be documented in this file.

## [1.1.0] - 2026-04-22

### Added
- **Transit certificate chain support** — three new methods on `ITransitEngine` for associating X.509 certificates with Transit signing keys and retrieving the end-entity serial at signing time. Motivated by regulatory signing flows (e.g., STP/Banxico) that require the cert serial to be embedded alongside the Vault-produced signature.
  - `SetCertificateChainAsync(keyName, pemCertificateChain, keyVersion?, ct)` — `POST /transit/keys/:name/set-certificate`
  - `GetCertificateChainAsync(keyName, version?, ct)` — `GET /transit/export/certificate-chain/:name(/:version)`; returns `null` when no certificate is set (or Vault < 1.16)
  - `GetCertificateSerialAsync(keyName, version?, format, ct)` — parses the first cert in the chain and returns its serial as decimal (default) or uppercase hex
- **`SerialFormat` enum** (`Hex`, `Decimal`) for serial-number output selection
- **`TransitKeyInfo.CertificateChain`** — populated from Vault's `certificate_chain` field when calling `GetKeyInfoAsync`
- **Raw HTTP escape hatch** — `IVaultClient.SendRawRequestAsync<TResponse>(method, relativePath, body?, ct)` for Vault endpoints not covered by VaultSharp. Automatically attaches the current Vault token. 404 → `null`; other non-success → `VaultOperationException`.
- **`VaultOperationException`** — new exception type for raw-HTTP failures (includes status code, response body, path).

### Notes
- `TransitSignRequest.SaltLength` continues to be a no-op because VaultSharp 1.17.5.1's `SignRequestOptions` does not expose a salt-length property. Forwarding SaltLength would require replacing the VaultSharp sign path with raw HTTP and is out of scope for 1.1.0.

## [1.0.2] - 2026-02-20

### Changed
- **Eager Authentication for DI Client** - The `IVaultClient` singleton registered via `AddVaultaX()` now authenticates eagerly during service resolution. `IsAuthenticated` returns `true` immediately after resolving the client from DI, without needing to call `AuthenticateAsync()` first.

### Fixed
- **IsAuthenticated false on fresh DI client** - Previously, the DI-registered `IVaultClient` was a separate lazy instance from the configuration provider client. Consumers resolving `IVaultClient` from DI would get `IsAuthenticated = false` until an explicit operation was performed. This caused issues with startup validation patterns that checked `IsAuthenticated` before any Vault operation.

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
