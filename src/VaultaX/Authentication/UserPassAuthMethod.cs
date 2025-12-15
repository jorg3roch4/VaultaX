using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.UserPass;

namespace VaultaX.Authentication;

/// <summary>
/// Username and Password authentication method.
/// </summary>
public sealed class UserPassAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "UserPass";

    /// <summary>
    /// Creates a new UserPass authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public UserPassAuthMethod(AuthenticationOptions options) : base(options)
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
        if (string.IsNullOrWhiteSpace(Options.Username))
        {
            throw new VaultaXConfigurationException(
                "Username is required for UserPass authentication.",
                "VaultaX:Authentication:Username");
        }

        var password = GetRequiredEnvVar(Options.PasswordEnvVar, "UserPass Password");
        var mountPath = GetMountPath("userpass");

        return new UserPassAuthMethodInfo(mountPath, Options.Username, password);
    }
}
