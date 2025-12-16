using System;
using System.Collections.Generic;

namespace VaultaX.Configuration;

/// <summary>
/// Main configuration options for VaultaX.
/// </summary>
public sealed class VaultaXOptions
{
    /// <summary>
    /// The configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "VaultaX";

    /// <summary>
    /// Enables or disables VaultaX completely.
    /// When false, VaultaX does nothing and configuration falls back to appsettings.
    /// Typically false in development, true in production.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Vault server address (e.g., https://vault.company.com:8200).
    /// Required when Enabled is true.
    /// </summary>
    public string Address { get; set; } = string.Empty;

    /// <summary>
    /// Mount point for the KV secrets engine (default: "secret").
    /// </summary>
    public string MountPoint { get; set; } = "secret";

    /// <summary>
    /// Base path for the application's secrets in Vault.
    /// Secrets are looked up at: {MountPoint}/{BasePath}/{SecretPath}
    /// Example: "myapp/prod" results in secrets at "secret/myapp/prod/database"
    /// </summary>
    public string BasePath { get; set; } = string.Empty;

    /// <summary>
    /// Version of the KV secrets engine (1 or 2). Default: 2
    /// KV v2 supports versioning and metadata.
    /// </summary>
    public int KvVersion { get; set; } = 2;

    /// <summary>
    /// Skip SSL certificate validation.
    /// WARNING: Only use in development environments.
    /// </summary>
    public bool SkipCertificateValidation { get; set; }

    /// <summary>
    /// Authentication configuration.
    /// </summary>
    public AuthenticationOptions Authentication { get; set; } = new();

    /// <summary>
    /// Secret reload configuration.
    /// </summary>
    public ReloadOptions Reload { get; set; } = new();

    /// <summary>
    /// Token renewal configuration.
    /// </summary>
    public TokenRenewalOptions TokenRenewal { get; set; } = new();

    /// <summary>
    /// Mappings from Vault secrets to configuration keys.
    /// </summary>
    public List<SecretMappingOptions> Mappings { get; set; } = [];
}

/// <summary>
/// Authentication configuration for connecting to Vault.
/// </summary>
public sealed class AuthenticationOptions
{
    /// <summary>
    /// Authentication method to use.
    /// Supported values: AppRole, Token, Kubernetes, Ldap, Jwt, Aws, Azure, GitHub, Certificate, UserPass, RADIUS, Custom
    /// </summary>
    public string Method { get; set; } = "AppRole";

    /// <summary>
    /// Mount path for the auth method (default depends on the method).
    /// Examples: "auth/approle", "auth/kubernetes", "auth/ldap"
    /// Leave empty to use the default mount path for the method.
    /// </summary>
    public string MountPath { get; set; } = string.Empty;

    // ==================== Common Properties ====================

    /// <summary>
    /// Token or credential for authentication.
    /// Used by: Token, JWT, GitHub methods.
    /// Supports: environment variable name, "env:VAR_NAME", or "static:value" (dev only).
    /// Default: "VAULT_TOKEN"
    /// </summary>
    public string Token { get; set; } = "VAULT_TOKEN";

    /// <summary>
    /// Role name for authentication.
    /// Used by: Kubernetes, JWT, AWS, Azure, Certificate methods.
    /// </summary>
    public string? Role { get; set; }

    /// <summary>
    /// Username for authentication.
    /// Used by: LDAP, UserPass, RADIUS methods.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Password for authentication.
    /// Used by: LDAP, UserPass, RADIUS methods.
    /// Supports: environment variable name, "env:VAR_NAME", or "static:value" (dev only).
    /// </summary>
    public string? Password { get; set; }

    // ==================== AppRole Authentication ====================

    /// <summary>
    /// [AppRole] The Role ID for AppRole authentication.
    /// </summary>
    public string? RoleId { get; set; }

    /// <summary>
    /// [AppRole] Secret ID for AppRole authentication.
    /// Supports: environment variable name, "env:VAR_NAME", or "static:value" (dev only).
    /// Default: "VAULT_SECRET_ID"
    /// </summary>
    public string SecretId { get; set; } = "VAULT_SECRET_ID";

    // ==================== Kubernetes Authentication ====================

    /// <summary>
    /// [Kubernetes] Path to the service account token file.
    /// Default: "/var/run/secrets/kubernetes.io/serviceaccount/token"
    /// </summary>
    public string ServiceAccountTokenPath { get; set; } = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    // ==================== AWS Authentication ====================

    /// <summary>
    /// [AWS] AWS region for STS calls.
    /// </summary>
    public string? Region { get; set; }

    /// <summary>
    /// [AWS] Authentication type: "iam" or "ec2". Default: "iam"
    /// </summary>
    public string AuthType { get; set; } = "iam";

    // ==================== Azure Authentication ====================

    /// <summary>
    /// [Azure] The Azure AD resource (audience) for the token.
    /// </summary>
    public string? Resource { get; set; }

    // ==================== Certificate Authentication ====================

    /// <summary>
    /// [Certificate] Path to the client certificate file (PFX/P12).
    /// </summary>
    public string? CertificatePath { get; set; }

    /// <summary>
    /// [Certificate] Password for the certificate file.
    /// Supports: environment variable name, "env:VAR_NAME", or "static:value" (dev only).
    /// </summary>
    public string? CertificatePassword { get; set; }

    // ==================== Custom Authentication ====================

    /// <summary>
    /// [Custom] Path for custom auth method (e.g., "auth/custom/login").
    /// </summary>
    public string? CustomPath { get; set; }

    /// <summary>
    /// [Custom] Value for custom authentication.
    /// Supports: environment variable name, "env:VAR_NAME", or "static:value" (dev only).
    /// </summary>
    public string? CustomValue { get; set; }

    // ==================== Helper Methods ====================

    /// <summary>
    /// Gets the Secret ID from the configured source.
    /// </summary>
    public string? GetSecretId() => GetEnvVar(SecretId);

    /// <summary>
    /// Gets the token from the configured source.
    /// </summary>
    public string? GetToken() => GetEnvVar(Token);

    /// <summary>
    /// Gets the password from the configured source.
    /// </summary>
    public string? GetPassword() => GetEnvVar(Password);

    /// <summary>
    /// Gets the certificate password from the configured source.
    /// </summary>
    public string? GetCertificatePassword() => GetEnvVar(CertificatePassword);

    /// <summary>
    /// Gets the custom auth value from the configured source.
    /// </summary>
    public string? GetCustomAuthValue() => GetEnvVar(CustomValue);

    private static string? GetEnvVar(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return null;

        // Support static values with "static:" prefix (for development/testing only)
        // Format: "static:your-secret-value"
        if (name.StartsWith("static:", StringComparison.OrdinalIgnoreCase))
            return name[7..]; // Return everything after "static:"

        // Support explicit env var prefix "env:"
        // Format: "env:MY_VAR_NAME"
        if (name.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
            return Environment.GetEnvironmentVariable(name[4..]);

        // Default: treat as environment variable name
        return Environment.GetEnvironmentVariable(name);
    }
}

/// <summary>
/// Configuration for automatic secret reloading.
/// </summary>
public sealed class ReloadOptions
{
    /// <summary>
    /// Enables automatic reloading when secrets change in Vault.
    /// Uses IOptionsMonitor/IOptionsSnapshot for configuration updates.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Interval in seconds to check for secret changes. Default: 300 (5 minutes).
    /// Lower values increase load on Vault but provide faster updates.
    /// </summary>
    public int IntervalSeconds { get; set; } = 300;
}

/// <summary>
/// Configuration for automatic token renewal.
/// </summary>
public sealed class TokenRenewalOptions
{
    /// <summary>
    /// Enables automatic token renewal before expiration.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Percentage of token TTL at which to trigger renewal. Default: 80.
    /// If the token has a 1-hour TTL, renewal will occur at ~48 minutes.
    /// </summary>
    public int ThresholdPercent { get; set; } = 80;

    /// <summary>
    /// Interval in seconds to check if renewal is needed. Default: 300 (5 minutes).
    /// </summary>
    public int CheckIntervalSeconds { get; set; } = 300;

    /// <summary>
    /// Maximum number of consecutive renewal failures before giving up. Default: 3.
    /// After max failures, the service will attempt re-authentication.
    /// </summary>
    public int MaxConsecutiveFailures { get; set; } = 3;
}

/// <summary>
/// Mapping from a Vault secret to configuration keys.
/// </summary>
public sealed class SecretMappingOptions
{
    /// <summary>
    /// Path to the secret in Vault, relative to BasePath.
    /// Example: "database" looks up {MountPoint}/{BasePath}/database
    /// </summary>
    public string SecretPath { get; set; } = string.Empty;

    /// <summary>
    /// Mapping of Vault secret keys to configuration keys.
    /// Key: The key name within the Vault secret
    /// Value: The configuration key in IConfiguration
    ///
    /// Example:
    /// {
    ///   "connectionString": "ConnectionStrings:DefaultConnection",
    ///   "username": "Database:Username"
    /// }
    /// </summary>
    public Dictionary<string, string> Bindings { get; set; } = [];
}
