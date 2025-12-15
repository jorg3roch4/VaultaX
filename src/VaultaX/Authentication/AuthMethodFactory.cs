using System;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;

namespace VaultaX.Authentication;

/// <summary>
/// Factory for creating authentication method instances.
/// </summary>
public static class AuthMethodFactory
{
    /// <summary>
    /// Creates an authentication method based on the configured method name.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    /// <returns>The authentication method instance.</returns>
    /// <exception cref="VaultaXConfigurationException">
    /// Thrown when the authentication method is not recognized.
    /// </exception>
    public static IAuthMethod Create(AuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return options.Method?.ToLowerInvariant() switch
        {
            "approle" => new AppRoleAuthMethod(options),
            "token" => new TokenAuthMethod(options),
            "kubernetes" or "k8s" => new KubernetesAuthMethod(options),
            "ldap" => new LdapAuthMethod(options),
            "jwt" or "oidc" => new JwtOidcAuthMethod(options),
            "aws" => new AwsAuthMethod(options),
            "azure" => new AzureAuthMethod(options),
            "github" => new GitHubAuthMethod(options),
            "cert" or "certificate" or "tls" => new CertificateAuthMethod(options),
            "userpass" => new UserPassAuthMethod(options),
            "radius" => new RadiusAuthMethod(options),
            "custom" => new CustomAuthMethod(options),
            null or "" => throw new VaultaXConfigurationException(
                "Authentication method is not specified.",
                "VaultaX:Authentication:Method"),
            _ => throw new VaultaXConfigurationException(
                $"Unknown authentication method: '{options.Method}'. " +
                "Supported methods: AppRole, Token, Kubernetes, LDAP, JWT, AWS, Azure, GitHub, Certificate, UserPass, RADIUS, Custom.",
                "VaultaX:Authentication:Method")
        };
    }

    /// <summary>
    /// Gets the list of supported authentication method names.
    /// </summary>
    public static readonly string[] SupportedMethods =
    [
        "AppRole",
        "Token",
        "Kubernetes",
        "LDAP",
        "JWT",
        "AWS",
        "Azure",
        "GitHub",
        "Certificate",
        "UserPass",
        "RADIUS",
        "Custom"
    ];
}
