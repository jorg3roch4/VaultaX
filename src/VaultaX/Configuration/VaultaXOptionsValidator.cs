using System;
using VaultaX.Exceptions;

namespace VaultaX.Configuration;

/// <summary>
/// Validates VaultaX configuration options.
/// </summary>
public static class VaultaXOptionsValidator
{
    /// <summary>
    /// Validates the configuration options and throws if invalid.
    /// </summary>
    /// <param name="options">The options to validate.</param>
    /// <exception cref="VaultaXConfigurationException">
    /// Thrown when the configuration is invalid.
    /// </exception>
    public static void Validate(VaultaXOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!options.Enabled)
        {
            // If not enabled, no validation needed
            return;
        }

        // Validate address
        if (string.IsNullOrWhiteSpace(options.Address))
        {
            throw new VaultaXConfigurationException(
                "VaultaX:Address is required when Enabled is true.",
                "VaultaX:Address");
        }

        if (!Uri.TryCreate(options.Address, UriKind.Absolute, out var uri) ||
            (uri.Scheme != "http" && uri.Scheme != "https"))
        {
            throw new VaultaXConfigurationException(
                $"VaultaX:Address must be a valid HTTP(S) URL. Got: {options.Address}",
                "VaultaX:Address");
        }

        // Validate KV version
        if (options.KvVersion is not (1 or 2))
        {
            throw new VaultaXConfigurationException(
                $"VaultaX:KvVersion must be 1 or 2. Got: {options.KvVersion}",
                "VaultaX:KvVersion");
        }

        // Validate authentication
        ValidateAuthentication(options.Authentication);

        // Validate mappings
        if (options.Mappings.Count == 0)
        {
            throw new VaultaXConfigurationException(
                "VaultaX:Mappings must contain at least one secret mapping.",
                "VaultaX:Mappings");
        }

        foreach (var mapping in options.Mappings)
        {
            ValidateMapping(mapping);
        }

        // Validate token renewal options
        if (options.TokenRenewal.Enabled)
        {
            if (options.TokenRenewal.ThresholdPercent is < 1 or > 99)
            {
                throw new VaultaXConfigurationException(
                    "VaultaX:TokenRenewal:ThresholdPercent must be between 1 and 99.",
                    "VaultaX:TokenRenewal:ThresholdPercent");
            }

            if (options.TokenRenewal.CheckIntervalSeconds < 10)
            {
                throw new VaultaXConfigurationException(
                    "VaultaX:TokenRenewal:CheckIntervalSeconds must be at least 10.",
                    "VaultaX:TokenRenewal:CheckIntervalSeconds");
            }
        }

        // Validate reload options
        if (options.Reload.Enabled)
        {
            if (options.Reload.IntervalSeconds < 30)
            {
                throw new VaultaXConfigurationException(
                    "VaultaX:Reload:IntervalSeconds must be at least 30.",
                    "VaultaX:Reload:IntervalSeconds");
            }
        }
    }

    private static void ValidateAuthentication(AuthenticationOptions auth)
    {
        if (string.IsNullOrWhiteSpace(auth.Method))
        {
            throw new VaultaXConfigurationException(
                "VaultaX:Authentication:Method is required.",
                "VaultaX:Authentication:Method");
        }

        var method = auth.Method.ToLowerInvariant();

        switch (method)
        {
            case "approle":
                if (string.IsNullOrWhiteSpace(auth.RoleId))
                {
                    throw new VaultaXConfigurationException(
                        "VaultaX:Authentication:RoleId is required for AppRole authentication.",
                        "VaultaX:Authentication:RoleId");
                }
                var secretId = auth.GetSecretId();
                if (string.IsNullOrWhiteSpace(secretId))
                {
                    throw new VaultaXConfigurationException(
                        $"SecretId source '{auth.SecretId}' for AppRole is not set or empty.",
                        "VaultaX:Authentication:SecretId");
                }
                break;

            case "token":
                var token = auth.GetToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    throw new VaultaXConfigurationException(
                        $"Token source '{auth.Token}' for Vault Token is not set or empty.",
                        "VaultaX:Authentication:Token");
                }
                break;

            case "kubernetes":
            case "k8s":
                if (string.IsNullOrWhiteSpace(auth.Role))
                {
                    throw new VaultaXConfigurationException(
                        "VaultaX:Authentication:Role is required for Kubernetes authentication.",
                        "VaultaX:Authentication:Role");
                }
                break;

            case "ldap":
            case "userpass":
            case "radius":
                if (string.IsNullOrWhiteSpace(auth.Username))
                {
                    throw new VaultaXConfigurationException(
                        $"VaultaX:Authentication:Username is required for {method} authentication.",
                        "VaultaX:Authentication:Username");
                }
                break;

            case "jwt":
            case "oidc":
                if (string.IsNullOrWhiteSpace(auth.Role))
                {
                    throw new VaultaXConfigurationException(
                        "VaultaX:Authentication:Role is required for JWT authentication.",
                        "VaultaX:Authentication:Role");
                }
                break;

            case "aws":
                if (string.IsNullOrWhiteSpace(auth.Role))
                {
                    throw new VaultaXConfigurationException(
                        "VaultaX:Authentication:Role is required for AWS authentication.",
                        "VaultaX:Authentication:Role");
                }
                break;

            case "azure":
                if (string.IsNullOrWhiteSpace(auth.Role))
                {
                    throw new VaultaXConfigurationException(
                        "VaultaX:Authentication:Role is required for Azure authentication.",
                        "VaultaX:Authentication:Role");
                }
                break;

            case "github":
                var githubToken = auth.GetToken();
                if (string.IsNullOrWhiteSpace(githubToken))
                {
                    throw new VaultaXConfigurationException(
                        $"Token source '{auth.Token}' for GitHub token is not set or empty.",
                        "VaultaX:Authentication:Token");
                }
                break;

            case "cert":
            case "certificate":
            case "tls":
                if (string.IsNullOrWhiteSpace(auth.CertificatePath))
                {
                    throw new VaultaXConfigurationException(
                        "VaultaX:Authentication:CertificatePath is required for Certificate authentication.",
                        "VaultaX:Authentication:CertificatePath");
                }
                break;

            case "custom":
                if (string.IsNullOrWhiteSpace(auth.CustomPath))
                {
                    throw new VaultaXConfigurationException(
                        "VaultaX:Authentication:CustomPath is required for Custom authentication.",
                        "VaultaX:Authentication:CustomPath");
                }
                break;
        }
    }

    private static void ValidateMapping(SecretMappingOptions mapping)
    {
        if (string.IsNullOrWhiteSpace(mapping.SecretPath))
        {
            throw new VaultaXConfigurationException(
                "Each VaultaX:Mappings entry must have a non-empty SecretPath.",
                "VaultaX:Mappings:SecretPath");
        }

        if (mapping.Bindings.Count == 0)
        {
            throw new VaultaXConfigurationException(
                $"VaultaX:Mappings['{mapping.SecretPath}']:Bindings must contain at least one binding.",
                $"VaultaX:Mappings:{mapping.SecretPath}:Bindings");
        }

        foreach (var binding in mapping.Bindings)
        {
            if (string.IsNullOrWhiteSpace(binding.Key))
            {
                throw new VaultaXConfigurationException(
                    $"VaultaX:Mappings['{mapping.SecretPath}']:Bindings contains an empty Vault key.",
                    $"VaultaX:Mappings:{mapping.SecretPath}:Bindings");
            }

            if (string.IsNullOrWhiteSpace(binding.Value))
            {
                throw new VaultaXConfigurationException(
                    $"VaultaX:Mappings['{mapping.SecretPath}']:Bindings['{binding.Key}'] has an empty configuration key.",
                    $"VaultaX:Mappings:{mapping.SecretPath}:Bindings:{binding.Key}");
            }
        }
    }
}
