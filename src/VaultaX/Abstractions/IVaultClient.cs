using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace VaultaX.Abstractions;

/// <summary>
/// High-level abstraction for interacting with HashiCorp Vault.
/// </summary>
public interface IVaultClient
{
    /// <summary>
    /// Indicates whether the client is currently authenticated.
    /// </summary>
    bool IsAuthenticated { get; }

    /// <summary>
    /// The current token's time-to-live, or null if not authenticated or token has no TTL.
    /// </summary>
    TimeSpan? TokenTimeToLive { get; }

    /// <summary>
    /// Indicates whether the current token is renewable.
    /// </summary>
    bool IsTokenRenewable { get; }

    /// <summary>
    /// Authenticates with Vault using the configured authentication method.
    /// </summary>
    Task AuthenticateAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Renews the current authentication token.
    /// </summary>
    /// <returns>The new token TTL after renewal.</returns>
    Task<TimeSpan> RenewTokenAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads a secret from the KV secrets engine.
    /// </summary>
    /// <param name="path">The secret path (relative to the configured base path).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A dictionary of key-value pairs from the secret.</returns>
    Task<IDictionary<string, object?>> ReadSecretAsync(
        string path,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads a secret and deserializes it to the specified type.
    /// </summary>
    /// <typeparam name="T">The type to deserialize to.</typeparam>
    /// <param name="path">The secret path (relative to the configured base path).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The deserialized secret data.</returns>
    Task<T> ReadSecretAsync<T>(
        string path,
        CancellationToken cancellationToken = default) where T : class, new();

    /// <summary>
    /// Writes a secret to the KV secrets engine.
    /// </summary>
    /// <param name="path">The secret path (relative to the configured base path).</param>
    /// <param name="data">The key-value pairs to store.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task WriteSecretAsync(
        string path,
        IDictionary<string, object?> data,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a secret from the KV secrets engine.
    /// For KV v2, this performs a soft delete (marks as deleted but can be recovered).
    /// </summary>
    /// <param name="path">The secret path (relative to the configured base path).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task DeleteSecretAsync(
        string path,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the metadata for a secret (KV v2 only).
    /// </summary>
    /// <param name="path">The secret path (relative to the configured base path).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Secret metadata including version information.</returns>
    Task<SecretMetadata?> GetSecretMetadataAsync(
        string path,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the underlying VaultSharp client for advanced operations.
    /// Use this for operations not covered by the high-level API.
    /// </summary>
    VaultSharp.IVaultClient GetUnderlyingClient();
}

/// <summary>
/// Metadata about a secret in Vault.
/// </summary>
public sealed class SecretMetadata
{
    /// <summary>
    /// Current version number of the secret.
    /// </summary>
    public int CurrentVersion { get; init; }

    /// <summary>
    /// Oldest version available in the secret's history.
    /// </summary>
    public int OldestVersion { get; init; }

    /// <summary>
    /// When the secret was created.
    /// </summary>
    public DateTimeOffset CreatedTime { get; init; }

    /// <summary>
    /// When the secret was last updated.
    /// </summary>
    public DateTimeOffset UpdatedTime { get; init; }

    /// <summary>
    /// Maximum number of versions to keep.
    /// </summary>
    public int MaxVersions { get; init; }

    /// <summary>
    /// Whether CAS (Check-And-Set) is required for writes.
    /// </summary>
    public bool CasRequired { get; init; }
}
