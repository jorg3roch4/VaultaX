using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using VaultaX.HealthChecks;

namespace VaultaX.Extensions;

/// <summary>
/// Extension methods for adding VaultaX health checks.
/// </summary>
public static class HealthChecksBuilderExtensions
{
    /// <summary>
    /// Adds a health check for HashiCorp Vault connectivity.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="name">The name of the health check (default: "vaultax").</param>
    /// <param name="failureStatus">The health status to report on failure (default: Unhealthy).</param>
    /// <param name="tags">Optional tags to associate with the health check.</param>
    /// <param name="timeout">Optional timeout for the health check.</param>
    /// <returns>The health checks builder for chaining.</returns>
    /// <remarks>
    /// This health check verifies:
    /// - Vault server connectivity
    /// - Vault initialization status
    /// - Vault seal status
    /// - Authentication token validity
    /// - Token expiration (warns if less than 5 minutes remaining)
    ///
    /// Example:
    /// <code>
    /// builder.Services.AddHealthChecks()
    ///     .AddVaultaX()
    ///     .AddSqlServer(...);
    /// </code>
    /// </remarks>
    public static IHealthChecksBuilder AddVaultaX(
        this IHealthChecksBuilder builder,
        string name = "vaultax",
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.Add(new HealthCheckRegistration(
            name,
            sp => sp.GetRequiredService<VaultHealthCheck>(),
            failureStatus,
            tags,
            timeout));
    }

    /// <summary>
    /// Adds the VaultaX health check with custom configuration.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="configure">Action to configure the health check options.</param>
    /// <returns>The health checks builder for chaining.</returns>
    /// <remarks>
    /// Example:
    /// <code>
    /// builder.Services.AddHealthChecks()
    ///     .AddVaultaX(options =>
    ///     {
    ///         options.Name = "vault-primary";
    ///         options.Tags = new[] { "vault", "secrets" };
    ///         options.FailureStatus = HealthStatus.Degraded;
    ///     });
    /// </code>
    /// </remarks>
    public static IHealthChecksBuilder AddVaultaX(
        this IHealthChecksBuilder builder,
        Action<VaultHealthCheckOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new VaultHealthCheckOptions();
        configure(options);

        return builder.Add(new HealthCheckRegistration(
            options.Name,
            sp => sp.GetRequiredService<VaultHealthCheck>(),
            options.FailureStatus,
            options.Tags,
            options.Timeout));
    }
}

/// <summary>
/// Options for configuring the VaultaX health check.
/// </summary>
public sealed class VaultHealthCheckOptions
{
    /// <summary>
    /// Gets or sets the name of the health check.
    /// </summary>
    public string Name { get; set; } = "vaultax";

    /// <summary>
    /// Gets or sets the health status to report on failure.
    /// </summary>
    public HealthStatus? FailureStatus { get; set; }

    /// <summary>
    /// Gets or sets the tags to associate with the health check.
    /// </summary>
    public IEnumerable<string>? Tags { get; set; }

    /// <summary>
    /// Gets or sets the timeout for the health check.
    /// </summary>
    public TimeSpan? Timeout { get; set; }
}
