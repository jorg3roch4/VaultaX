using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Kubernetes;

namespace VaultaX.Authentication;

/// <summary>
/// Kubernetes authentication method for workloads running in Kubernetes.
/// Uses the pod's service account token to authenticate with Vault.
/// </summary>
public sealed class KubernetesAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "Kubernetes";

    /// <summary>
    /// Creates a new Kubernetes authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public KubernetesAuthMethod(AuthenticationOptions options) : base(options)
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
                "Role is required for Kubernetes authentication.",
                "VaultaX:Authentication:Role");
        }

        var tokenPath = Options.ServiceAccountTokenPath;
        if (string.IsNullOrWhiteSpace(tokenPath))
        {
            tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        }

        if (!File.Exists(tokenPath))
        {
            throw new VaultaXConfigurationException(
                $"Kubernetes service account token file not found at: {tokenPath}. " +
                "Ensure the pod has a service account with a mounted token.",
                "VaultaX:Authentication:ServiceAccountTokenPath");
        }

        var jwt = File.ReadAllText(tokenPath).Trim();
        var mountPath = GetMountPath("kubernetes");

        return new KubernetesAuthMethodInfo(mountPath, Options.Role, jwt);
    }
}
