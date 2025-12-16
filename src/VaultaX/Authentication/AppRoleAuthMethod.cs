using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.AppRole;

namespace VaultaX.Authentication;

/// <summary>
/// AppRole authentication method for machine-to-machine authentication.
/// Recommended for most application deployments.
/// </summary>
public sealed class AppRoleAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "AppRole";

    /// <summary>
    /// Creates a new AppRole authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public AppRoleAuthMethod(AuthenticationOptions options) : base(options)
    {
    }

    /// <inheritdoc />
    public override Task<AuthResult> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        // Validation is done in GetAuthMethodInfo
        // The actual authentication is performed by VaultSharp when creating the client
        // This method returns a placeholder result; actual token info comes from VaultSharp
        return Task.FromResult(new AuthResult
        {
            Token = string.Empty, // Will be populated by VaultSharp
            LeaseDuration = TimeSpan.Zero,
            Renewable = true
        });
    }

    /// <inheritdoc />
    public override IAuthMethodInfo GetAuthMethodInfo()
    {
        if (string.IsNullOrWhiteSpace(Options.RoleId))
        {
            throw new VaultaXConfigurationException(
                "RoleId is required for AppRole authentication.",
                "VaultaX:Authentication:RoleId");
        }

        var secretId = GetRequiredEnvVar(Options.SecretId, "AppRole SecretId");
        var mountPath = GetMountPath("approle");

        return new AppRoleAuthMethodInfo(mountPath, Options.RoleId, secretId);
    }
}
