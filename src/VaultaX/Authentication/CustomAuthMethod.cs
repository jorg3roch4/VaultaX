using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Custom;

namespace VaultaX.Authentication;

/// <summary>
/// Custom authentication method for auth backends not directly supported.
/// </summary>
public sealed class CustomAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "Custom";

    /// <summary>
    /// Creates a new Custom authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public CustomAuthMethod(AuthenticationOptions options) : base(options)
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
        if (string.IsNullOrWhiteSpace(Options.CustomAuthPath))
        {
            throw new VaultaXConfigurationException(
                "CustomAuthPath is required for Custom authentication.",
                "VaultaX:Authentication:CustomAuthPath");
        }

        var authValue = GetRequiredEnvVar(Options.CustomAuthEnvVar, "Custom Auth Value");

        // The custom auth method expects a delegate that returns Task<AuthInfo>
        return new CustomAuthMethodInfo(Options.CustomAuthPath, async () =>
        {
            return new VaultSharp.V1.Commons.AuthInfo
            {
                ClientToken = authValue
            };
        });
    }
}
