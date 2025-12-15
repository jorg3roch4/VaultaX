using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;

namespace VaultaX.Engines.KeyValue;

/// <summary>
/// Implementation of the Key-Value secrets engine (supports both v1 and v2).
/// </summary>
public sealed class KeyValueEngine : IKeyValueEngine
{
    private readonly IVaultClient _vaultClient;
    private readonly VaultaXOptions _options;
    private readonly ILogger<KeyValueEngine>? _logger;

    /// <summary>
    /// Creates a new Key-Value engine instance.
    /// </summary>
    public KeyValueEngine(
        IVaultClient vaultClient,
        IOptions<VaultaXOptions> options,
        ILogger<KeyValueEngine>? logger = null)
    {
        _vaultClient = vaultClient ?? throw new ArgumentNullException(nameof(vaultClient));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    /// <inheritdoc />
    public string EngineType => $"kv-v{_options.KvVersion}";

    /// <inheritdoc />
    public string MountPoint => _options.MountPoint;

    /// <inheritdoc />
    public async Task<IDictionary<string, object?>> ReadAsync(
        string path,
        int? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        _logger?.LogDebug("Reading secret from KV engine at {Path}, version: {Version}", path, version ?? -1);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var fullPath = BuildPath(path);

            if (_options.KvVersion == 2)
            {
                var secret = await client.V1.Secrets.KeyValue.V2.ReadSecretAsync(
                    path: fullPath,
                    version: version,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                return secret?.Data?.Data ?? new Dictionary<string, object?>();
            }
            else
            {
                var secret = await client.V1.Secrets.KeyValue.V1.ReadSecretAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                return secret?.Data ?? new Dictionary<string, object?>();
            }
        }
        catch (VaultSharp.Core.VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            throw new VaultSecretNotFoundException(path, ex);
        }
        catch (Exception ex) when (ex is not VaultSecretNotFoundException)
        {
            _logger?.LogError(ex, "Failed to read secret from {Path}", path);
            throw new VaultaXException($"Failed to read secret from {path}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task<T> ReadAsync<T>(
        string path,
        int? version = null,
        CancellationToken cancellationToken = default) where T : class, new()
    {
        var data = await ReadAsync(path, version, cancellationToken).ConfigureAwait(false);

        try
        {
            var json = JsonSerializer.Serialize(data);
            return JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new T();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to deserialize secret from {Path} to {Type}", path, typeof(T).Name);
            throw new VaultaXException($"Failed to deserialize secret from {path}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task WriteAsync(
        string path,
        IDictionary<string, object?> data,
        int? checkAndSet = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(data);

        _logger?.LogDebug("Writing secret to KV engine at {Path}", path);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var fullPath = BuildPath(path);

            if (_options.KvVersion == 2)
            {
                await client.V1.Secrets.KeyValue.V2.WriteSecretAsync(
                    path: fullPath,
                    data: data,
                    checkAndSet: checkAndSet,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);
            }
            else
            {
                await client.V1.Secrets.KeyValue.V1.WriteSecretAsync(
                    path: fullPath,
                    values: data,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);
            }

            _logger?.LogInformation("Secret written successfully to {Path}", path);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to write secret to {Path}", path);
            throw new VaultaXException($"Failed to write secret to {path}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task DeleteAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        _logger?.LogDebug("Deleting secret at {Path}", path);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var fullPath = BuildPath(path);

            if (_options.KvVersion == 2)
            {
                await client.V1.Secrets.KeyValue.V2.DeleteSecretAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);
            }
            else
            {
                await client.V1.Secrets.KeyValue.V1.DeleteSecretAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);
            }

            _logger?.LogInformation("Secret deleted successfully from {Path}", path);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to delete secret at {Path}", path);
            throw new VaultaXException($"Failed to delete secret at {path}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> ListAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var listPath = string.IsNullOrWhiteSpace(path) ? string.Empty : path.Trim('/');

        _logger?.LogDebug("Listing secrets at {Path}", listPath);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var fullPath = BuildPath(listPath);

            if (_options.KvVersion == 2)
            {
                var result = await client.V1.Secrets.KeyValue.V2.ReadSecretPathsAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                return result?.Data?.Keys?.ToList() ?? [];
            }
            else
            {
                var result = await client.V1.Secrets.KeyValue.V1.ReadSecretPathsAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                return result?.Data?.Keys?.ToList() ?? [];
            }
        }
        catch (VaultSharp.Core.VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return [];
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to list secrets at {Path}", listPath);
            throw new VaultaXException($"Failed to list secrets at {listPath}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task<SecretMetadata?> GetMetadataAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        if (_options.KvVersion != 2)
        {
            _logger?.LogWarning("Metadata is only available for KV v2");
            return null;
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        _logger?.LogDebug("Getting metadata for {Path}", path);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var fullPath = BuildPath(path);

            var metadata = await client.V1.Secrets.KeyValue.V2.ReadSecretMetadataAsync(
                path: fullPath,
                mountPoint: _options.MountPoint).ConfigureAwait(false);

            if (metadata?.Data == null)
                return null;

            return new SecretMetadata
            {
                CurrentVersion = metadata.Data.CurrentVersion,
                OldestVersion = metadata.Data.OldestVersion,
                CreatedTime = DateTimeOffset.TryParse(metadata.Data.CreatedTime, out var ct) ? ct : DateTimeOffset.MinValue,
                UpdatedTime = DateTimeOffset.TryParse(metadata.Data.UpdatedTime, out var ut) ? ut : DateTimeOffset.MinValue,
                MaxVersions = 0, // Property not available in VaultSharp 1.17.5.1
                CasRequired = false // Property not available in VaultSharp 1.17.5.1
            };
        }
        catch (VaultSharp.Core.VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get metadata for {Path}", path);
            throw new VaultaXException($"Failed to get metadata for {path}: {ex.Message}", ex);
        }
    }

    private string BuildPath(string path)
    {
        var basePath = _options.BasePath?.Trim('/') ?? string.Empty;
        var secretPath = path.Trim('/');

        return string.IsNullOrEmpty(basePath)
            ? secretPath
            : $"{basePath}/{secretPath}";
    }
}
