using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using VaultaX.Authentication;
using VaultaX.Exceptions;
using VaultSharp;
using VaultSharp.V1.Commons;

namespace VaultaX.Configuration;

/// <summary>
/// Configuration provider that loads secrets from HashiCorp Vault.
/// Secrets are loaded at startup and can be reloaded on change.
/// </summary>
public sealed class VaultConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly VaultaXOptions _options;
    private readonly ILogger _logger;
    private IVaultClient? _vaultClient;
    private Timer? _reloadTimer;
    private Timer? _renewalTimer;
    private CancellationTokenSource? _cts;
    private Dictionary<string, int> _secretVersions = new();
    private bool _disposed;

    /// <summary>
    /// Creates a new Vault configuration provider.
    /// </summary>
    public VaultConfigurationProvider(VaultaXOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = CreateLogger();
    }

    /// <inheritdoc />
    public override void Load()
    {
        try
        {
            _logger.LogInformation("VaultaX: Loading secrets from {Address}", _options.Address);

            _cts = new CancellationTokenSource();
            _vaultClient = CreateVaultClient();

            // Load all secrets synchronously (required by IConfigurationProvider)
            LoadSecretsAsync().GetAwaiter().GetResult();

            // Start background services if enabled
            StartBackgroundServices();

            _logger.LogInformation(
                "VaultaX: Successfully loaded {Count} secret mappings from {MappingCount} paths",
                Data.Count,
                _options.Mappings.Count);
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "VaultaX: Failed to load secrets from Vault at {Address}", _options.Address);
            throw new VaultaXException($"Failed to load secrets from Vault: {ex.Message}", ex);
        }
    }

    private async Task LoadSecretsAsync()
    {
        foreach (var mapping in _options.Mappings)
        {
            if (string.IsNullOrWhiteSpace(mapping.SecretPath))
            {
                _logger.LogWarning("VaultaX: Skipping mapping with empty SecretPath");
                continue;
            }

            await LoadSecretMappingAsync(mapping).ConfigureAwait(false);
        }
    }

    private async Task LoadSecretMappingAsync(SecretMappingOptions mapping)
    {
        var fullPath = BuildFullPath(mapping.SecretPath);

        try
        {
            _logger.LogDebug("VaultaX: Loading secret from path {Path}", fullPath);

            IDictionary<string, object?> secretData;
            int? version = null;

            if (_options.KvVersion == 2)
            {
                var secret = await _vaultClient!.V1.Secrets.KeyValue.V2.ReadSecretAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                secretData = secret?.Data?.Data ?? new Dictionary<string, object?>();
                version = secret?.Data?.Metadata?.Version;

                if (version.HasValue)
                {
                    _secretVersions[mapping.SecretPath] = version.Value;
                }
            }
            else
            {
                var secret = await _vaultClient!.V1.Secrets.KeyValue.V1.ReadSecretAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                secretData = secret?.Data ?? new Dictionary<string, object?>();
            }

            // Apply bindings
            foreach (var binding in mapping.Bindings)
            {
                var vaultKey = binding.Key;
                var configKey = binding.Value;

                if (secretData.TryGetValue(vaultKey, out var value))
                {
                    var stringValue = value?.ToString();
                    Set(configKey, stringValue);

                    _logger.LogDebug(
                        "VaultaX: Mapped {SecretPath}/{VaultKey} -> {ConfigKey}",
                        mapping.SecretPath,
                        vaultKey,
                        configKey);
                }
                else
                {
                    _logger.LogWarning(
                        "VaultaX: Key '{VaultKey}' not found in secret '{SecretPath}'",
                        vaultKey,
                        mapping.SecretPath);
                }
            }
        }
        catch (VaultSharp.Core.VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            _logger.LogError("VaultaX: Secret not found at path '{Path}'", fullPath);
            throw new VaultSecretNotFoundException(fullPath, ex);
        }
        catch (Exception ex) when (ex is not VaultSecretNotFoundException)
        {
            _logger.LogError(ex, "VaultaX: Failed to load secret from path '{Path}'", fullPath);
            throw;
        }
    }

    private void StartBackgroundServices()
    {
        // Start token renewal if enabled
        if (_options.TokenRenewal.Enabled)
        {
            var interval = TimeSpan.FromSeconds(_options.TokenRenewal.CheckIntervalSeconds);
            _renewalTimer = new Timer(
                callback: _ => RenewTokenIfNeededAsync().ConfigureAwait(false).GetAwaiter().GetResult(),
                state: null,
                dueTime: interval,
                period: interval);

            _logger.LogInformation(
                "VaultaX: Token renewal started (interval: {Interval}s, threshold: {Threshold}%)",
                _options.TokenRenewal.CheckIntervalSeconds,
                _options.TokenRenewal.ThresholdPercent);
        }

        // Start secret reload if enabled
        if (_options.Reload.Enabled)
        {
            var interval = TimeSpan.FromSeconds(_options.Reload.IntervalSeconds);
            _reloadTimer = new Timer(
                callback: _ => CheckForChangesAsync().ConfigureAwait(false).GetAwaiter().GetResult(),
                state: null,
                dueTime: interval,
                period: interval);

            _logger.LogInformation(
                "VaultaX: Secret reload started (interval: {Interval}s)",
                _options.Reload.IntervalSeconds);
        }
    }

    private async Task RenewTokenIfNeededAsync()
    {
        if (_cts?.IsCancellationRequested ?? true)
            return;

        try
        {
            var tokenInfo = await _vaultClient!.V1.Auth.Token.LookupSelfAsync().ConfigureAwait(false);
            var ttl = tokenInfo.Data.TimeToLive;
            var creationTtl = tokenInfo.Data.CreationTimeToLive;

            if (creationTtl == 0)
            {
                _logger.LogDebug("VaultaX: Token has no TTL, skipping renewal check");
                return;
            }

            var elapsedPercent = 100.0 * (1 - ((double)ttl / creationTtl));

            if (elapsedPercent >= _options.TokenRenewal.ThresholdPercent)
            {
                _logger.LogInformation(
                    "VaultaX: Token at {ElapsedPercent:F1}% of TTL, renewing...",
                    elapsedPercent);

                if (tokenInfo.Data.Renewable)
                {
                    var result = await _vaultClient.V1.Auth.Token.RenewSelfAsync().ConfigureAwait(false);
                    _logger.LogInformation(
                        "VaultaX: Token renewed successfully, new TTL: {Ttl}s",
                        result.LeaseDurationSeconds);
                }
                else
                {
                    _logger.LogWarning("VaultaX: Token is not renewable, re-authentication required");
                    // Re-create the client to force re-authentication
                    _vaultClient = CreateVaultClient();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "VaultaX: Failed to renew token");
        }
    }

    private async Task CheckForChangesAsync()
    {
        if (_cts?.IsCancellationRequested ?? true)
            return;

        if (_options.KvVersion != 2)
        {
            _logger.LogDebug("VaultaX: Secret change detection requires KV v2");
            return;
        }

        try
        {
            var hasChanges = false;

            foreach (var mapping in _options.Mappings)
            {
                var fullPath = BuildFullPath(mapping.SecretPath);

                try
                {
                    var metadata = await _vaultClient!.V1.Secrets.KeyValue.V2.ReadSecretMetadataAsync(
                        path: fullPath,
                        mountPoint: _options.MountPoint).ConfigureAwait(false);

                    var currentVersion = metadata?.Data?.CurrentVersion ?? 0;

                    if (_secretVersions.TryGetValue(mapping.SecretPath, out var previousVersion))
                    {
                        if (currentVersion > previousVersion)
                        {
                            _logger.LogInformation(
                                "VaultaX: Secret '{SecretPath}' changed (version {Old} -> {New})",
                                mapping.SecretPath,
                                previousVersion,
                                currentVersion);

                            hasChanges = true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "VaultaX: Failed to check metadata for '{SecretPath}'", mapping.SecretPath);
                }
            }

            if (hasChanges)
            {
                _logger.LogInformation("VaultaX: Reloading secrets due to detected changes");

                // Reload all secrets
                await LoadSecretsAsync().ConfigureAwait(false);

                // Notify listeners of the change
                OnReload();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "VaultaX: Failed to check for secret changes");
        }
    }

    private IVaultClient CreateVaultClient()
    {
        var authMethod = AuthMethodFactory.Create(_options.Authentication);
        var authMethodInfo = authMethod.GetAuthMethodInfo();

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

        return new VaultClient(settings);
    }

    private string BuildFullPath(string path)
    {
        var basePath = _options.BasePath?.Trim('/') ?? string.Empty;
        var secretPath = path.Trim('/');

        return string.IsNullOrEmpty(basePath)
            ? secretPath
            : $"{basePath}/{secretPath}";
    }

    private static ILogger CreateLogger()
    {
        try
        {
            var factory = new Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory();
            return factory.CreateLogger<VaultConfigurationProvider>();
        }
        catch
        {
            return NullLogger.Instance;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        _cts?.Cancel();
        _cts?.Dispose();

        _reloadTimer?.Dispose();
        _renewalTimer?.Dispose();

        _vaultClient = null;
    }
}
