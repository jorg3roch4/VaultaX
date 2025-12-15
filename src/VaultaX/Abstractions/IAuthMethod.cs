using System;
using System.Threading;
using System.Threading.Tasks;

namespace VaultaX.Abstractions;

/// <summary>
/// Represents an authentication method for connecting to Vault.
/// </summary>
public interface IAuthMethod
{
    /// <summary>
    /// The name of this authentication method (e.g., "AppRole", "Kubernetes").
    /// </summary>
    string MethodName { get; }

    /// <summary>
    /// Authenticates with Vault and returns the authentication result.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The authentication result containing the token and metadata.</returns>
    Task<AuthResult> AuthenticateAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the VaultSharp auth method info for this authentication method.
    /// </summary>
    /// <returns>The auth method info to use with VaultSharp.</returns>
    VaultSharp.V1.AuthMethods.IAuthMethodInfo GetAuthMethodInfo();
}

/// <summary>
/// Result of a successful authentication with Vault.
/// </summary>
public sealed record AuthResult
{
    /// <summary>
    /// The authentication token.
    /// </summary>
    public required string Token { get; init; }

    /// <summary>
    /// The token's lease duration (time-to-live).
    /// </summary>
    public required TimeSpan LeaseDuration { get; init; }

    /// <summary>
    /// Indicates whether the token can be renewed.
    /// </summary>
    public required bool Renewable { get; init; }

    /// <summary>
    /// The accessor for this token (can be used to look up the token without having it).
    /// </summary>
    public string? Accessor { get; init; }

    /// <summary>
    /// The policies attached to this token.
    /// </summary>
    public string[]? Policies { get; init; }

    /// <summary>
    /// Additional metadata returned by Vault.
    /// </summary>
    public System.Collections.Generic.IDictionary<string, string>? Metadata { get; init; }
}
