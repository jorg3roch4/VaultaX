using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VaultaX.Abstractions;
using VaultaX.Configuration;

namespace VaultaX.HealthChecks;

/// <summary>
/// Health check for HashiCorp Vault connectivity and authentication status.
/// </summary>
public sealed class VaultHealthCheck : IHealthCheck
{
    private readonly IVaultClient _vaultClient;
    private readonly VaultaXOptions _options;
    private readonly ILogger<VaultHealthCheck>? _logger;

    /// <summary>
    /// Creates a new Vault health check.
    /// </summary>
    public VaultHealthCheck(
        IVaultClient vaultClient,
        IOptions<VaultaXOptions> options,
        ILogger<VaultHealthCheck>? logger = null)
    {
        _vaultClient = vaultClient ?? throw new ArgumentNullException(nameof(vaultClient));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return HealthCheckResult.Healthy("VaultaX is disabled", new Dictionary<string, object>
            {
                ["enabled"] = false
            });
        }

        try
        {
            // Ensure the client is authenticated before checking health
            // This is necessary because the DI-registered IVaultClient may not have been used yet
            if (!_vaultClient.IsAuthenticated)
            {
                try
                {
                    await _vaultClient.AuthenticateAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "VaultaX health check: Initial authentication attempt failed, will check Vault status anyway");
                }
            }

            var client = _vaultClient.GetUnderlyingClient();

            // Check Vault health
            var healthStatus = await client.V1.System.GetHealthStatusAsync().ConfigureAwait(false);

            var data = new Dictionary<string, object>
            {
                ["enabled"] = true,
                ["address"] = _options.Address,
                ["environment"] = _options.BasePath,
                ["kvVersion"] = _options.KvVersion,
                ["initialized"] = healthStatus.Initialized,
                ["sealed"] = healthStatus.Sealed,
                ["standby"] = healthStatus.Standby,
                ["clusterName"] = healthStatus.ClusterName ?? "N/A",
                ["version"] = healthStatus.Version ?? "N/A"
            };

            // Add token info if authenticated
            if (_vaultClient.IsAuthenticated)
            {
                data["authenticated"] = true;

                if (_vaultClient.TokenTimeToLive.HasValue)
                {
                    data["tokenTtl"] = _vaultClient.TokenTimeToLive.Value.ToString();
                    data["tokenRenewable"] = _vaultClient.IsTokenRenewable;
                }
            }
            else
            {
                data["authenticated"] = false;
            }

            // Determine health status
            if (healthStatus.Sealed)
            {
                _logger?.LogWarning("VaultaX health check: Vault is sealed");
                return HealthCheckResult.Unhealthy("Vault is sealed", data: data);
            }

            if (!healthStatus.Initialized)
            {
                _logger?.LogWarning("VaultaX health check: Vault is not initialized");
                return HealthCheckResult.Unhealthy("Vault is not initialized", data: data);
            }

            if (healthStatus.Standby)
            {
                // Standby is okay for reads in HA mode
                return HealthCheckResult.Degraded("Vault is in standby mode", data: data);
            }

            // Check token validity
            if (!_vaultClient.IsAuthenticated)
            {
                _logger?.LogWarning("VaultaX health check: Not authenticated");
                return HealthCheckResult.Degraded("Not authenticated with Vault", data: data);
            }

            // Check if token is about to expire
            // Note: Root tokens and some service tokens have no TTL (infinite lifetime)
            if (_vaultClient.TokenTimeToLive.HasValue)
            {
                var ttl = _vaultClient.TokenTimeToLive.Value;
                // Only warn about expiration if token has a positive TTL that's expiring soon
                // Skip this check for tokens with no TTL (root tokens) or negative TTL (already handled by renewal)
                if (ttl > TimeSpan.Zero && ttl < TimeSpan.FromMinutes(5))
                {
                    _logger?.LogWarning("VaultaX health check: Token expiring soon ({Ttl})", ttl);
                    return HealthCheckResult.Degraded(
                        $"Token expires in {ttl.TotalMinutes:F1} minutes",
                        data: data);
                }
            }

            return HealthCheckResult.Healthy("Vault is healthy", data);
        }
        catch (VaultSharp.Core.VaultApiException ex)
        {
            _logger?.LogError(ex, "VaultaX health check failed: Vault API error");
            return HealthCheckResult.Unhealthy(
                $"Vault API error: {ex.Message}",
                exception: ex,
                data: new Dictionary<string, object>
                {
                    ["enabled"] = true,
                    ["address"] = _options.Address,
                    ["error"] = ex.Message,
                    ["httpStatus"] = (int)ex.HttpStatusCode
                });
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "VaultaX health check failed");
            return HealthCheckResult.Unhealthy(
                $"Health check failed: {ex.Message}",
                exception: ex,
                data: new Dictionary<string, object>
                {
                    ["enabled"] = true,
                    ["address"] = _options.Address,
                    ["error"] = ex.Message
                });
        }
    }
}
