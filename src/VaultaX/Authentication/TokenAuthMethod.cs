using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;

namespace VaultaX.Authentication;

/// <summary>
/// Token authentication method using a pre-existing Vault token.
/// Typically used for development or when a token is provided externally.
/// </summary>
public sealed class TokenAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "Token";

    /// <summary>
    /// Creates a new Token authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public TokenAuthMethod(AuthenticationOptions options) : base(options)
    {
    }

    /// <inheritdoc />
    public override Task<AuthResult> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new AuthResult
        {
            Token = string.Empty,
            LeaseDuration = TimeSpan.Zero,
            Renewable = false // Token auth tokens may or may not be renewable
        });
    }

    /// <inheritdoc />
    public override IAuthMethodInfo GetAuthMethodInfo()
    {
        var token = GetRequiredEnvVar(Options.Token, "Vault Token");
        return new TokenAuthMethodInfo(token);
    }
}
