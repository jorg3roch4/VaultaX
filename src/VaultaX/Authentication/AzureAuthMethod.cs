using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Azure;

namespace VaultaX.Authentication;

/// <summary>
/// Azure authentication method for workloads running on Azure.
/// Uses Azure Managed Identity to authenticate with Vault.
/// </summary>
public sealed class AzureAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "Azure";

    /// <summary>
    /// Creates a new Azure authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public AzureAuthMethod(AuthenticationOptions options) : base(options)
    {
    }

    /// <inheritdoc />
    public override Task<AuthResult> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new AuthResult
        {
            Token = string.Empty,
            LeaseDuration = TimeSpan.Zero,
            Renewable = true
        });
    }

    /// <inheritdoc />
    public override IAuthMethodInfo GetAuthMethodInfo()
    {
        if (string.IsNullOrWhiteSpace(Options.Role))
        {
            throw new VaultaXConfigurationException(
                "Role is required for Azure authentication.",
                "VaultaX:Authentication:Role");
        }

        var mountPath = GetMountPath("azure");

        // Get JWT token from Azure Managed Identity (from environment variable)
        var jwt = GetRequiredEnvVar("AZURE_JWT_TOKEN", "Azure JWT Token");

        return new AzureAuthMethodInfo(
            mountPoint: mountPath,
            roleName: Options.Role,
            jwt: jwt);
    }
}
