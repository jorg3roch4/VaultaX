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
    /// Supported values: AppRole, Token, Kubernetes, Ldap, Jwt, Aws, Azure, GitHub, Certificate, UserPass, Custom
    /// </summary>
    public string Method { get; set; } = "AppRole";

    /// <summary>
    /// Mount path for the auth method (default depends on the method).
    /// Examples: "auth/approle", "auth/kubernetes", "auth/ldap"
    /// Leave empty to use the default mount path for the method.
    /// </summary>
    public string MountPath { get; set; } = string.Empty;

    // ==================== AppRole Authentication ====================

    /// <summary>
    /// [AppRole] The Role ID for AppRole authentication.
    /// </summary>
    public string? RoleId { get; set; }

    /// <summary>
    /// [AppRole] Environment variable name containing the Secret ID.
    /// Default: "VAULT_SECRET_ID"
    /// The Secret ID should NEVER be stored in configuration files.
    /// </summary>
    public string SecretIdEnvVar { get; set; } = "VAULT_SECRET_ID";

    // ==================== Token Authentication ====================

    /// <summary>
    /// [Token] Environment variable name containing the Vault token.
    /// Default: "VAULT_TOKEN"
    /// </summary>
    public string TokenEnvVar { get; set; } = "VAULT_TOKEN";

    // ==================== Kubernetes Authentication ====================

    /// <summary>
    /// [Kubernetes] The Vault role to authenticate as.
    /// </summary>
    public string? KubernetesRole { get; set; }

    /// <summary>
    /// [Kubernetes] Path to the service account token file.
    /// Default: "/var/run/secrets/kubernetes.io/serviceaccount/token"
    /// </summary>
    public string ServiceAccountTokenPath { get; set; } = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    // ==================== LDAP / UserPass Authentication ====================

    /// <summary>
    /// [LDAP/UserPass] Username for authentication.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// [LDAP/UserPass] Environment variable name containing the password.
    /// </summary>
    public string? PasswordEnvVar { get; set; }

    // ==================== JWT/OIDC Authentication ====================

    /// <summary>
    /// [JWT/OIDC] The Vault role to authenticate as.
    /// </summary>
    public string? JwtRole { get; set; }

    /// <summary>
    /// [JWT/OIDC] Environment variable name containing the JWT token.
    /// </summary>
    public string? JwtTokenEnvVar { get; set; }

    // ==================== AWS Authentication ====================

    /// <summary>
    /// [AWS] The Vault role to authenticate as.
    /// </summary>
    public string? AwsRole { get; set; }

    /// <summary>
    /// [AWS] AWS region for STS calls.
    /// </summary>
    public string? AwsRegion { get; set; }

    /// <summary>
    /// [AWS] Authentication type: "iam" or "ec2". Default: "iam"
    /// </summary>
    public string AwsAuthType { get; set; } = "iam";

    // ==================== Azure Authentication ====================

    /// <summary>
    /// [Azure] The Vault role to authenticate as.
    /// </summary>
    public string? AzureRole { get; set; }

    /// <summary>
    /// [Azure] The Azure AD resource (audience) for the token.
    /// </summary>
    public string? AzureResource { get; set; }

    // ==================== GitHub Authentication ====================

    /// <summary>
    /// [GitHub] Environment variable name containing the GitHub personal access token.
    /// </summary>
    public string? GitHubTokenEnvVar { get; set; }

    // ==================== Certificate Authentication ====================

    /// <summary>
    /// [Certificate] Path to the client certificate file (PFX/P12).
    /// </summary>
    public string? CertificatePath { get; set; }

    /// <summary>
    /// [Certificate] Environment variable name containing the certificate password.
    /// </summary>
    public string? CertificatePasswordEnvVar { get; set; }

    /// <summary>
    /// [Certificate] The Vault role to authenticate as.
    /// </summary>
    public string? CertificateRole { get; set; }

    // ==================== RADIUS Authentication ====================

    /// <summary>
    /// [RADIUS] Username for RADIUS authentication.
    /// </summary>
    public string? RadiusUsername { get; set; }

    /// <summary>
    /// [RADIUS] Environment variable name containing the RADIUS password.
    /// </summary>
    public string? RadiusPasswordEnvVar { get; set; }

    // ==================== Custom Authentication ====================

    /// <summary>
    /// [Custom] For custom auth methods, the path to call (e.g., "auth/custom/login").
    /// </summary>
    public string? CustomAuthPath { get; set; }

    /// <summary>
    /// [Custom] Environment variable name containing the custom auth token or payload.
    /// </summary>
    public string? CustomAuthEnvVar { get; set; }

    // ==================== Helper Methods ====================

    /// <summary>
    /// Gets the Secret ID from the configured environment variable.
    /// </summary>
    public string? GetSecretId() => GetEnvVar(SecretIdEnvVar);

    /// <summary>
    /// Gets the token from the configured environment variable.
    /// </summary>
    public string? GetToken() => GetEnvVar(TokenEnvVar);

    /// <summary>
    /// Gets the password from the configured environment variable.
    /// </summary>
    public string? GetPassword() => GetEnvVar(PasswordEnvVar);

    /// <summary>
    /// Gets the JWT from the configured environment variable.
    /// </summary>
    public string? GetJwtToken() => GetEnvVar(JwtTokenEnvVar);

    /// <summary>
    /// Gets the GitHub token from the configured environment variable.
    /// </summary>
    public string? GetGitHubToken() => GetEnvVar(GitHubTokenEnvVar);

    /// <summary>
    /// Gets the certificate password from the configured environment variable.
    /// </summary>
    public string? GetCertificatePassword() => GetEnvVar(CertificatePasswordEnvVar);

    /// <summary>
    /// Gets the RADIUS password from the configured environment variable.
    /// </summary>
    public string? GetRadiusPassword() => GetEnvVar(RadiusPasswordEnvVar);

    /// <summary>
    /// Gets the custom auth value from the configured environment variable.
    /// </summary>
    public string? GetCustomAuthValue() => GetEnvVar(CustomAuthEnvVar);

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
