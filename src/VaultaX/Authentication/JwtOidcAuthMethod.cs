using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.JWT;

namespace VaultaX.Authentication;

/// <summary>
/// JWT/OIDC authentication method for token-based authentication.
/// </summary>
public sealed class JwtOidcAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "JWT";

    /// <summary>
    /// Creates a new JWT/OIDC authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public JwtOidcAuthMethod(AuthenticationOptions options) : base(options)
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
        if (string.IsNullOrWhiteSpace(Options.JwtRole))
        {
            throw new VaultaXConfigurationException(
                "JwtRole is required for JWT authentication.",
                "VaultaX:Authentication:JwtRole");
        }

        var jwt = GetRequiredEnvVar(Options.JwtTokenEnvVar, "JWT Token");
        var mountPath = GetMountPath("jwt");

        return new JWTAuthMethodInfo(mountPath, Options.JwtRole, jwt);
    }
}
