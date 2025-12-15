using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VaultaX.Abstractions;
using VaultaX.Configuration;

namespace VaultaX.BackgroundServices;

/// <summary>
/// Background service that automatically renews Vault tokens before they expire.
/// </summary>
public sealed class TokenRenewalService : BackgroundService
{
    private readonly IVaultClient _vaultClient;
    private readonly VaultaXOptions _options;
    private readonly ILogger<TokenRenewalService> _logger;
    private int _consecutiveFailures;

    /// <summary>
    /// Creates a new token renewal service.
    /// </summary>
    public TokenRenewalService(
        IVaultClient vaultClient,
        IOptions<VaultaXOptions> options,
        ILogger<TokenRenewalService> logger)
    {
        _vaultClient = vaultClient ?? throw new ArgumentNullException(nameof(vaultClient));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled || !_options.TokenRenewal.Enabled)
        {
            _logger.LogInformation("VaultaX: Token renewal service is disabled");
            return;
        }

        _logger.LogInformation(
            "VaultaX: Token renewal service started (interval: {Interval}s, threshold: {Threshold}%)",
            _options.TokenRenewal.CheckIntervalSeconds,
            _options.TokenRenewal.ThresholdPercent);

        // Initial delay to let the application start
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false);

        var interval = TimeSpan.FromSeconds(_options.TokenRenewal.CheckIntervalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAndRenewTokenAsync(stoppingToken).ConfigureAwait(false);
                _consecutiveFailures = 0;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _consecutiveFailures++;
                _logger.LogError(ex,
                    "VaultaX: Token renewal failed (attempt {Attempt}/{Max})",
                    _consecutiveFailures,
                    _options.TokenRenewal.MaxConsecutiveFailures);

                if (_consecutiveFailures >= _options.TokenRenewal.MaxConsecutiveFailures)
                {
                    _logger.LogCritical(
                        "VaultaX: Max consecutive token renewal failures reached ({Max}). " +
                        "Attempting re-authentication...",
                        _options.TokenRenewal.MaxConsecutiveFailures);

                    try
                    {
                        await _vaultClient.AuthenticateAsync(stoppingToken).ConfigureAwait(false);
                        _consecutiveFailures = 0;
                        _logger.LogInformation("VaultaX: Re-authentication successful");
                    }
                    catch (Exception authEx)
                    {
                        _logger.LogCritical(authEx, "VaultaX: Re-authentication failed");
                    }
                }
            }

            try
            {
                await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }

        _logger.LogInformation("VaultaX: Token renewal service stopped");
    }

    private async Task CheckAndRenewTokenAsync(CancellationToken cancellationToken)
    {
        var ttl = _vaultClient.TokenTimeToLive;

        if (!ttl.HasValue || ttl.Value == TimeSpan.Zero)
        {
            _logger.LogDebug("VaultaX: Token has no TTL, skipping renewal check");
            return;
        }

        // We can't calculate elapsed percentage without original TTL
        // So we'll renew when remaining time is less than threshold
        // Assuming typical token TTL, we use the remaining time directly
        var remainingSeconds = ttl.Value.TotalSeconds;

        // If remaining time is less than the check interval * 2, renew
        var renewalThreshold = _options.TokenRenewal.CheckIntervalSeconds * 2;

        if (remainingSeconds <= renewalThreshold)
        {
            _logger.LogInformation(
                "VaultaX: Token has {Remaining:F0}s remaining, renewing...",
                remainingSeconds);

            if (_vaultClient.IsTokenRenewable)
            {
                var newTtl = await _vaultClient.RenewTokenAsync(cancellationToken).ConfigureAwait(false);
                _logger.LogInformation("VaultaX: Token renewed, new TTL: {Ttl}", newTtl);
            }
            else
            {
                _logger.LogWarning("VaultaX: Token is not renewable, re-authentication will be required");
            }
        }
        else
        {
            _logger.LogDebug("VaultaX: Token has {Remaining:F0}s remaining, no renewal needed", remainingSeconds);
        }
    }
}
