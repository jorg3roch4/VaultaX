using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.RADIUS;

namespace VaultaX.Authentication;

/// <summary>
/// RADIUS authentication method.
/// </summary>
public sealed class RadiusAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "RADIUS";

    /// <summary>
    /// Creates a new RADIUS authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public RadiusAuthMethod(AuthenticationOptions options) : base(options)
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
        if (string.IsNullOrWhiteSpace(Options.RadiusUsername))
        {
            throw new VaultaXConfigurationException(
                "RadiusUsername is required for RADIUS authentication.",
                "VaultaX:Authentication:RadiusUsername");
        }

        var password = GetRequiredEnvVar(Options.RadiusPasswordEnvVar, "RADIUS Password");
        var mountPath = GetMountPath("radius");

        return new RADIUSAuthMethodInfo(mountPath, Options.RadiusUsername, password);
    }
}
