using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VaultaX.Abstractions;
using VaultaX.Configuration;

namespace VaultaX.BackgroundServices;

/// <summary>
/// Background service that monitors Vault secrets for changes and triggers configuration reload.
/// </summary>
public sealed class SecretChangeWatcherService : BackgroundService
{
    private readonly IVaultClient _vaultClient;
    private readonly IConfiguration _configuration;
    private readonly VaultaXOptions _options;
    private readonly ILogger<SecretChangeWatcherService> _logger;
    private readonly Dictionary<string, int> _secretVersions = new();

    /// <summary>
    /// Event raised when secrets have changed and been reloaded.
    /// </summary>
    public event EventHandler<SecretsChangedEventArgs>? SecretsChanged;

    /// <summary>
    /// Creates a new secret change watcher service.
    /// </summary>
    public SecretChangeWatcherService(
        IVaultClient vaultClient,
        IConfiguration configuration,
        IOptions<VaultaXOptions> options,
        ILogger<SecretChangeWatcherService> logger)
    {
        _vaultClient = vaultClient ?? throw new ArgumentNullException(nameof(vaultClient));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled || !_options.Reload.Enabled)
        {
            _logger.LogInformation("VaultaX: Secret change watcher is disabled");
            return;
        }

        if (_options.KvVersion != 2)
        {
            _logger.LogWarning("VaultaX: Secret change detection requires KV v2. Watcher disabled.");
            return;
        }

        _logger.LogInformation(
            "VaultaX: Secret change watcher started (interval: {Interval}s)",
            _options.Reload.IntervalSeconds);

        // Initial delay and version capture
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken).ConfigureAwait(false);
        await CaptureInitialVersionsAsync(stoppingToken).ConfigureAwait(false);

        var interval = TimeSpan.FromSeconds(_options.Reload.IntervalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                await CheckForChangesAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "VaultaX: Error checking for secret changes");
            }
        }

        _logger.LogInformation("VaultaX: Secret change watcher stopped");
    }

    private async Task CaptureInitialVersionsAsync(CancellationToken cancellationToken)
    {
        var client = _vaultClient.GetUnderlyingClient();

        foreach (var mapping in _options.Mappings)
        {
            try
            {
                var fullPath = BuildFullPath(mapping.SecretPath);
                var metadata = await client.V1.Secrets.KeyValue.V2.ReadSecretMetadataAsync(
                    path: fullPath,
                    mountPoint: _options.MountPoint).ConfigureAwait(false);

                if (metadata?.Data != null)
                {
                    _secretVersions[mapping.SecretPath] = metadata.Data.CurrentVersion;
                    _logger.LogDebug(
                        "VaultaX: Captured initial version for '{SecretPath}': {Version}",
                        mapping.SecretPath,
                        metadata.Data.CurrentVersion);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "VaultaX: Failed to capture initial version for '{SecretPath}'",
                    mapping.SecretPath);
            }
        }
    }

    private async Task CheckForChangesAsync(CancellationToken cancellationToken)
    {
        var changedSecrets = new List<string>();
        var client = _vaultClient.GetUnderlyingClient();

        foreach (var mapping in _options.Mappings)
        {
            try
            {
                var fullPath = BuildFullPath(mapping.SecretPath);
                var metadata = await client.V1.Secrets.KeyValue.V2.ReadSecretMetadataAsync(
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

                        changedSecrets.Add(mapping.SecretPath);
                        _secretVersions[mapping.SecretPath] = currentVersion;
                    }
                }
                else
                {
                    _secretVersions[mapping.SecretPath] = currentVersion;
                }
            }
            catch (VaultSharp.Core.VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger.LogWarning("VaultaX: Secret '{SecretPath}' no longer exists", mapping.SecretPath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "VaultaX: Failed to check version for '{SecretPath}'",
                    mapping.SecretPath);
            }
        }

        if (changedSecrets.Count > 0)
        {
            _logger.LogInformation(
                "VaultaX: {Count} secret(s) changed, triggering reload",
                changedSecrets.Count);

            // Trigger configuration reload
            if (_configuration is IConfigurationRoot configRoot)
            {
                configRoot.Reload();
                _logger.LogInformation("VaultaX: Configuration reloaded");
            }

            // Raise event for subscribers
            SecretsChanged?.Invoke(this, new SecretsChangedEventArgs(changedSecrets));
        }
    }

    private string BuildFullPath(string path)
    {
        var basePath = _options.BasePath?.Trim('/') ?? string.Empty;
        var secretPath = path.Trim('/');

        return string.IsNullOrEmpty(basePath)
            ? secretPath
            : $"{basePath}/{secretPath}";
    }
}

/// <summary>
/// Event args for secrets changed events.
/// </summary>
public sealed class SecretsChangedEventArgs : EventArgs
{
    /// <summary>
    /// The list of secret paths that changed.
    /// </summary>
    public IReadOnlyList<string> ChangedSecrets { get; }

    /// <summary>
    /// Creates new secrets changed event args.
    /// </summary>
    public SecretsChangedEventArgs(IReadOnlyList<string> changedSecrets)
    {
        ChangedSecrets = changedSecrets;
    }
}
