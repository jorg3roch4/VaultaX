using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VaultaX.Authentication;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;

namespace VaultaX.Services;

/// <summary>
/// Wrapper around VaultSharp client providing high-level operations.
/// </summary>
public sealed class VaultClientWrapper : Abstractions.IVaultClient, IDisposable
{
    private readonly VaultaXOptions _options;
    private readonly ILogger<VaultClientWrapper>? _logger;
    private readonly Abstractions.IAuthMethod _authMethod;
    private VaultSharp.IVaultClient? _underlyingClient;
    private Abstractions.TokenInfo? _currentToken;
    private readonly object _clientLock = new();
    private bool _disposed;
    private bool _authenticationVerified;

    /// <summary>
    /// Creates a new Vault client wrapper.
    /// </summary>
    public VaultClientWrapper(IOptions<VaultaXOptions> options, ILogger<VaultClientWrapper>? logger = null)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
        _authMethod = AuthMethodFactory.Create(_options.Authentication);
    }

    /// <summary>
    /// Creates a new Vault client wrapper with explicit options.
    /// </summary>
    public VaultClientWrapper(VaultaXOptions options, ILogger<VaultClientWrapper>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
        _authMethod = AuthMethodFactory.Create(_options.Authentication);
    }

    /// <inheritdoc />
    public bool IsAuthenticated => _authenticationVerified || (_currentToken != null && !_currentToken.IsExpired);

    /// <inheritdoc />
    public TimeSpan? TokenTimeToLive => _currentToken?.RemainingTime;

    /// <inheritdoc />
    public bool IsTokenRenewable => _currentToken?.Renewable ?? false;

    /// <inheritdoc />
    public async Task AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("Authenticating with Vault using {Method}", _authMethod.MethodName);

        try
        {
            var client = GetOrCreateClient();

            // Force authentication by performing a token lookup
            var tokenInfo = await client.V1.Auth.Token.LookupSelfAsync().ConfigureAwait(false);

            _currentToken = new Abstractions.TokenInfo
            {
                Token = string.Empty, // Token is managed internally by VaultSharp
                CreatedAt = DateTimeOffset.UtcNow,
                LeaseDuration = TimeSpan.FromSeconds(tokenInfo.Data.TimeToLive),
                Renewable = tokenInfo.Data.Renewable
            };

            _authenticationVerified = true;

            _logger?.LogInformation(
                "Successfully authenticated with Vault. Token TTL: {Ttl}, Renewable: {Renewable}",
                _currentToken.LeaseDuration,
                _currentToken.Renewable);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to authenticate with Vault using {Method}", _authMethod.MethodName);
            throw new VaultAuthenticationException(
                $"Failed to authenticate with Vault using {_authMethod.MethodName}: {ex.Message}",
                _authMethod.MethodName,
                ex);
        }
    }

    /// <inheritdoc />
    public async Task<TimeSpan> RenewTokenAsync(CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("Renewing Vault token");

        try
        {
            var client = GetOrCreateClient();
            var result = await client.V1.Auth.Token.RenewSelfAsync().ConfigureAwait(false);

            var newTtl = TimeSpan.FromSeconds(result.LeaseDurationSeconds);

            _currentToken = new Abstractions.TokenInfo
            {
                Token = string.Empty,
                CreatedAt = DateTimeOffset.UtcNow,
                LeaseDuration = newTtl,
                Renewable = result.Renewable
            };

            _logger?.LogInformation("Token renewed successfully. New TTL: {Ttl}", newTtl);
            return newTtl;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to renew Vault token");
            throw new VaultTokenRenewalException("Failed to renew Vault token", ex);
        }
    }

    /// <inheritdoc />
    public async Task<IDictionary<string, object?>> ReadSecretAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = BuildFullPath(path);
        _logger?.LogDebug("Reading secret from {Path}", fullPath);

        try
        {
            var client = GetOrCreateClient();

            IDictionary<string, object?> result;

            if (_options.KvVersion == 2)
            {
                var secret = await client.V1.Secrets.KeyValue.V2.ReadSecretAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                result = secret?.Data?.Data ?? new Dictionary<string, object?>();
            }
            else
            {
                var secret = await client.V1.Secrets.KeyValue.V1.ReadSecretAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                result = secret?.Data ?? new Dictionary<string, object?>();
            }

            // Mark as authenticated after successful operation
            _authenticationVerified = true;
            return result;
        }
        catch (VaultSharp.Core.VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            throw new VaultSecretNotFoundException(fullPath, ex);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to read secret from {Path}", fullPath);
            throw new VaultaXException($"Failed to read secret from {fullPath}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task<T> ReadSecretAsync<T>(
        string path,
        CancellationToken cancellationToken = default) where T : class, new()
    {
        var data = await ReadSecretAsync(path, cancellationToken).ConfigureAwait(false);

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
            throw new VaultaXException($"Failed to deserialize secret: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task WriteSecretAsync(
        string path,
        IDictionary<string, object?> data,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(data);

        var fullPath = BuildFullPath(path);
        _logger?.LogDebug("Writing secret to {Path}", fullPath);

        try
        {
            var client = GetOrCreateClient();

            if (_options.KvVersion == 2)
            {
                await client.V1.Secrets.KeyValue.V2.WriteSecretAsync(
                    path: fullPath,
                    data: data,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);
            }
            else
            {
                await client.V1.Secrets.KeyValue.V1.WriteSecretAsync(
                    path: fullPath,
                    values: data,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);
            }

            _logger?.LogInformation("Secret written successfully to {Path}", fullPath);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to write secret to {Path}", fullPath);
            throw new VaultaXException($"Failed to write secret to {fullPath}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task DeleteSecretAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = BuildFullPath(path);
        _logger?.LogDebug("Deleting secret at {Path}", fullPath);

        try
        {
            var client = GetOrCreateClient();

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

            _logger?.LogInformation("Secret deleted successfully from {Path}", fullPath);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to delete secret at {Path}", fullPath);
            throw new VaultaXException($"Failed to delete secret at {fullPath}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task<Abstractions.SecretMetadata?> GetSecretMetadataAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        if (_options.KvVersion != 2)
        {
            _logger?.LogWarning("Metadata is only available for KV v2. Current version: {Version}", _options.KvVersion);
            return null;
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = BuildFullPath(path);
        _logger?.LogDebug("Getting metadata for {Path}", fullPath);

        try
        {
            var client = GetOrCreateClient();
            var metadata = await client.V1.Secrets.KeyValue.V2.ReadSecretMetadataAsync(
                path: fullPath,
                mountPoint: _options.MountPoint).ConfigureAwait(false);

            if (metadata?.Data == null)
                return null;

            return new Abstractions.SecretMetadata
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
            _logger?.LogError(ex, "Failed to get metadata for {Path}", fullPath);
            throw new VaultaXException($"Failed to get metadata for {fullPath}: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public VaultSharp.IVaultClient GetUnderlyingClient() => GetOrCreateClient();

    private static readonly JsonSerializerOptions RawJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private HttpClient? _rawHttpClient;
    private readonly object _rawHttpClientLock = new();

    /// <inheritdoc />
    public async Task<TResponse?> SendRawRequestAsync<TResponse>(
        HttpMethod method,
        string relativePath,
        object? body = null,
        CancellationToken cancellationToken = default)
        where TResponse : class
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);

        var trimmedPath = relativePath.TrimStart('/');
        var client = GetOrCreateClient();

        var token = await GetVaultTokenAsync(client).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new VaultOperationException(
                "Could not obtain a Vault token for raw HTTP request. Ensure the client is authenticated.");
        }

        var baseAddress = (_options.Address ?? string.Empty).TrimEnd('/');
        var requestUri = new Uri($"{baseAddress}/v1/{trimmedPath}", UriKind.Absolute);

        using var request = new HttpRequestMessage(method, requestUri);
        request.Headers.Add("X-Vault-Token", token);

        if (body is not null)
        {
            var json = JsonSerializer.Serialize(body, RawJsonOptions);
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        var http = GetRawHttpClient();
        _logger?.LogDebug("Raw Vault request {Method} {Path}", method.Method, trimmedPath);

        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new VaultOperationException(
                $"Vault returned {(int)response.StatusCode} for {method.Method} {trimmedPath}: {responseBody}",
                (int)response.StatusCode,
                responseBody,
                trimmedPath);
        }

        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<TResponse>(responseBody, RawJsonOptions);
        }
        catch (JsonException ex)
        {
            throw new VaultOperationException(
                $"Failed to deserialize Vault response for {method.Method} {trimmedPath}: {ex.Message}",
                (int)response.StatusCode,
                responseBody,
                trimmedPath);
        }
    }

    private HttpClient GetRawHttpClient()
    {
        if (_rawHttpClient != null)
        {
            return _rawHttpClient;
        }

        lock (_rawHttpClientLock)
        {
            if (_rawHttpClient != null)
            {
                return _rawHttpClient;
            }

            HttpMessageHandler handler;
            if (_options.SkipCertificateValidation)
            {
                handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                };
            }
            else
            {
                handler = new HttpClientHandler();
            }

            _rawHttpClient = new HttpClient(handler, disposeHandler: true);
            _rawHttpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return _rawHttpClient;
        }
    }

    private static async Task<string?> GetVaultTokenAsync(VaultSharp.IVaultClient client)
    {
        // Resolve the Vault token used for authentication, honouring the underlying
        // VaultSharp AuthMethodInfo. We must NOT pass the external IVaultClient to
        // AuthMethodInfo.GetVaultTokenAsync — that method expects VaultSharp's internal
        // Polymath. Doing so silently returns a null token, which then breaks the raw
        // HTTP escape hatch (Transit certificate chain / serial operations).
        var settings = client.Settings;
        var authInfo = settings?.AuthMethodInfo;
        if (authInfo is null)
        {
            return null;
        }

        // Strategy A: Token-based auth — the configured token is exposed as a public
        // string property (VaultToken). This is the common path for local/dev and for
        // production setups that inject a Vault token directly.
        if (authInfo is TokenAuthMethodInfo tokenInfo && !string.IsNullOrEmpty(tokenInfo.VaultToken))
        {
            return tokenInfo.VaultToken;
        }

        // Strategy B: Any other AuthMethodInfo subtype that surfaces the token via a
        // public instance string property named "VaultToken" (defensive fallback for
        // VaultSharp evolution across versions).
        var vaultTokenProp = authInfo.GetType().GetProperty(
            "VaultToken",
            BindingFlags.Public | BindingFlags.Instance);
        if (vaultTokenProp is not null && vaultTokenProp.PropertyType == typeof(string))
        {
            if (vaultTokenProp.GetValue(authInfo) is string propToken && !string.IsNullOrEmpty(propToken))
            {
                return propToken;
            }
        }

        // Strategy C: Fallback — reach into VaultSharp's internal Polymath on the
        // VaultClient implementation and invoke AuthMethodInfo.GetVaultTokenAsync with
        // the correct argument type. Uses reflection to stay forward-compatible.
        var polymath = GetPolymath(client);
        if (polymath is not null)
        {
            var method = authInfo.GetType().GetMethod(
                "GetVaultTokenAsync",
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

            if (method is not null)
            {
                var parameters = method.GetParameters();
                if (parameters.Length == 1 && parameters[0].ParameterType.IsInstanceOfType(polymath))
                {
                    var result = method.Invoke(authInfo, new[] { polymath });
                    if (result is Task<string> tokenTask)
                    {
                        return await tokenTask.ConfigureAwait(false);
                    }

                    if (result is Task task)
                    {
                        await task.ConfigureAwait(false);
                        var resultProperty = task.GetType().GetProperty("Result");
                        return resultProperty?.GetValue(task) as string;
                    }

                    return result as string;
                }
            }
        }

        return null;
    }

    private static object? GetPolymath(VaultSharp.IVaultClient client)
    {
        // VaultSharp.VaultClient stores its internal Polymath in a private field.
        // Walk the type hierarchy looking for a field or property named "_polymath"
        // or "Polymath" — field names have changed across VaultSharp versions.
        var type = client.GetType();
        while (type is not null)
        {
            var field = type.GetField(
                "_polymath",
                BindingFlags.NonPublic | BindingFlags.Instance);
            if (field is not null)
            {
                return field.GetValue(client);
            }

            var prop = type.GetProperty(
                "Polymath",
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            if (prop is not null)
            {
                return prop.GetValue(client);
            }

            type = type.BaseType;
        }

        return null;
    }

    private VaultSharp.IVaultClient GetOrCreateClient()
    {
        if (_underlyingClient != null)
            return _underlyingClient;

        lock (_clientLock)
        {
            if (_underlyingClient != null)
                return _underlyingClient;

            _logger?.LogDebug("Creating Vault client for {Address}", _options.Address);

            var authMethodInfo = _authMethod.GetAuthMethodInfo();

            var settings = new VaultClientSettings(_options.Address, authMethodInfo)
            {
                UseVaultTokenHeaderInsteadOfAuthorizationHeader = false,
                MyHttpClientProviderFunc = handler =>
                {
                    if (_options.SkipCertificateValidation)
                    {
                        var httpHandler = new HttpClientHandler
                        {
                            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                        };
                        return new HttpClient(httpHandler);
                    }
                    return new HttpClient();
                }
            };

            _underlyingClient = new VaultClient(settings);
            return _underlyingClient;
        }
    }

    private string BuildFullPath(string path)
    {
        var trimmedBase = _options.BasePath?.Trim('/') ?? string.Empty;
        var trimmedPath = path.Trim('/');

        return string.IsNullOrEmpty(trimmedBase)
            ? trimmedPath
            : $"{trimmedBase}/{trimmedPath}";
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        // VaultClient doesn't implement IDisposable, but we clean up our references
        _underlyingClient = null;
        _currentToken = null;
        _authenticationVerified = false;
        _rawHttpClient?.Dispose();
        _rawHttpClient = null;
    }
}
