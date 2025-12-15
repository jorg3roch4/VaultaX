using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.GitHub;

namespace VaultaX.Authentication;

/// <summary>
/// GitHub authentication method using GitHub personal access tokens.
/// </summary>
public sealed class GitHubAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "GitHub";

    /// <summary>
    /// Creates a new GitHub authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public GitHubAuthMethod(AuthenticationOptions options) : base(options)
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
        var token = GetRequiredEnvVar(Options.GitHubTokenEnvVar, "GitHub Personal Access Token");
        var mountPath = GetMountPath("github");

        return new GitHubAuthMethodInfo(mountPath, token);
    }
}
