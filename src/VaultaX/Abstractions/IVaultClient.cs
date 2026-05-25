using System;
using System.Collections.Generic;
using System.Net.Http;
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

    /// <summary>
    /// Sends a raw HTTP request to Vault for endpoints not covered by VaultSharp.
    /// The current Vault token is automatically attached via the <c>X-Vault-Token</c> header.
    /// Responses with HTTP 404 are translated to <c>null</c>; other non-success status codes throw
    /// <see cref="Exceptions.VaultOperationException"/>.
    /// </summary>
    /// <typeparam name="TResponse">Type to deserialize the JSON response body into.</typeparam>
    /// <param name="method">HTTP method (e.g., <see cref="HttpMethod.Get"/>, <see cref="HttpMethod.Post"/>).</param>
    /// <param name="relativePath">Vault path relative to the <c>/v1/</c> prefix (e.g., <c>"transit/keys/foo/set-certificate"</c>).</param>
    /// <param name="body">Optional request body — serialized to JSON. Use <c>null</c> for methods without a body.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The deserialized response body, or <c>null</c> when Vault returned 404.</returns>
    Task<TResponse?> SendRawRequestAsync<TResponse>(
        HttpMethod method,
        string relativePath,
        object? body = null,
        CancellationToken cancellationToken = default)
        where TResponse : class;
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
