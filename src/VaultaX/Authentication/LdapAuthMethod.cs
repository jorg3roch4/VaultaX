using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.LDAP;

namespace VaultaX.Authentication;

/// <summary>
/// LDAP authentication method for enterprise directory integration.
/// </summary>
public sealed class LdapAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "LDAP";

    /// <summary>
    /// Creates a new LDAP authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public LdapAuthMethod(AuthenticationOptions options) : base(options)
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
                "Username is required for LDAP authentication.",
                "VaultaX:Authentication:Username");
        }

        var password = GetRequiredEnvVar(Options.Password, "LDAP Password");
        var mountPath = GetMountPath("ldap");

        return new LDAPAuthMethodInfo(mountPath, Options.Username, password);
    }
}
