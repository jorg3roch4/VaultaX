using System;
using System.Threading;
using System.Threading.Tasks;

namespace VaultaX.Abstractions;

/// <summary>
/// Manages Vault authentication tokens, including automatic renewal.
/// </summary>
public interface ITokenManager
{
    /// <summary>
    /// Gets the current authentication token.
    /// If not authenticated, performs authentication first.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The current valid token.</returns>
    Task<string> GetTokenAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets information about the current token.
    /// </summary>
    TokenInfo? CurrentToken { get; }

    /// <summary>
    /// Forces a renewal of the current token if it's renewable.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RenewAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if renewal is needed and renews if necessary.
    /// </summary>
    /// <param name="thresholdPercent">The percentage of TTL at which to renew.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if renewal was performed, false otherwise.</returns>
    Task<bool> RenewIfNeededAsync(int thresholdPercent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Forces re-authentication (gets a new token instead of renewing).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task ReauthenticateAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the current token.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Event raised when a token is renewed.
    /// </summary>
    event EventHandler<TokenRenewedEventArgs>? TokenRenewed;

    /// <summary>
    /// Event raised when re-authentication occurs.
    /// </summary>
    event EventHandler<TokenReauthenticatedEventArgs>? TokenReauthenticated;

    /// <summary>
    /// Event raised when token renewal fails.
    /// </summary>
    event EventHandler<TokenRenewalFailedEventArgs>? TokenRenewalFailed;
}

/// <summary>
/// Information about a Vault token.
/// </summary>
public sealed record TokenInfo
{
    /// <summary>
    /// The token value.
    /// </summary>
    public required string Token { get; init; }

    /// <summary>
    /// When the token was created or last renewed.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// The token's lease duration.
    /// </summary>
    public required TimeSpan LeaseDuration { get; init; }

    /// <summary>
    /// When the token will expire.
    /// </summary>
    public DateTimeOffset ExpiresAt => CreatedAt + LeaseDuration;

    /// <summary>
    /// Whether the token is renewable.
    /// </summary>
    public required bool Renewable { get; init; }

    /// <summary>
    /// Remaining time before the token expires.
    /// </summary>
    public TimeSpan RemainingTime => ExpiresAt - DateTimeOffset.UtcNow;

    /// <summary>
    /// Percentage of the TTL that has elapsed (0-100).
    /// </summary>
    public double ElapsedPercent
    {
        get
        {
            if (LeaseDuration == TimeSpan.Zero)
                return 100;

            var elapsed = DateTimeOffset.UtcNow - CreatedAt;
            return Math.Min(100, (elapsed.TotalSeconds / LeaseDuration.TotalSeconds) * 100);
        }
    }

    /// <summary>
    /// Whether the token has expired.
    /// </summary>
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
}

/// <summary>
/// Event args for token renewal events.
/// </summary>
public sealed class TokenRenewedEventArgs : EventArgs
{
    /// <summary>
    /// The new lease duration after renewal.
    /// </summary>
    public required TimeSpan NewLeaseDuration { get; init; }

    /// <summary>
    /// When the renewal occurred.
    /// </summary>
    public required DateTimeOffset RenewedAt { get; init; }
}

/// <summary>
/// Event args for re-authentication events.
/// </summary>
public sealed class TokenReauthenticatedEventArgs : EventArgs
{
    /// <summary>
    /// The new token's lease duration.
    /// </summary>
    public required TimeSpan LeaseDuration { get; init; }

    /// <summary>
    /// When the re-authentication occurred.
    /// </summary>
    public required DateTimeOffset AuthenticatedAt { get; init; }

    /// <summary>
    /// The reason for re-authentication.
    /// </summary>
    public required string Reason { get; init; }
}

/// <summary>
/// Event args for token renewal failure events.
/// </summary>
public sealed class TokenRenewalFailedEventArgs : EventArgs
{
    /// <summary>
    /// The exception that caused the failure.
    /// </summary>
    public required Exception Exception { get; init; }

    /// <summary>
    /// Number of consecutive failures.
    /// </summary>
    public required int ConsecutiveFailures { get; init; }

    /// <summary>
    /// Whether re-authentication will be attempted.
    /// </summary>
    public required bool WillReauthenticate { get; init; }
}
