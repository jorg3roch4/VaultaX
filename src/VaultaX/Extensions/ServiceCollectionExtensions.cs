using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using VaultaX.Abstractions;
using VaultaX.BackgroundServices;
using VaultaX.Configuration;
using VaultaX.Engines.KeyValue;
using VaultaX.Engines.Pki;
using VaultaX.Engines.Transit;
using VaultaX.HealthChecks;
using VaultaX.Services;

namespace VaultaX.Extensions;

/// <summary>
/// Extension methods for registering VaultaX services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds VaultaX services to the dependency injection container.
    /// This includes the Vault client, secret engines, and optional background services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration to read VaultaX options from.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// This method registers:
    /// - IVaultClient for direct Vault operations
    /// - IKeyValueEngine for KV secret operations
    /// - ITransitEngine for encryption/signing (call AddVaultaXTransit separately for custom mount point)
    /// - IPkiEngine for PKI operations (call AddVaultaXPki separately for custom mount point)
    /// - Token renewal and secret change watcher services (if enabled in configuration)
    ///
    /// Example:
    /// <code>
    /// builder.Services.AddVaultaX(builder.Configuration);
    /// </code>
    /// </remarks>
    public static IServiceCollection AddVaultaX(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var options = configuration.GetSection(VaultaXOptions.SectionName).Get<VaultaXOptions>();

        // If not enabled, register nothing
        if (options == null || !options.Enabled)
        {
            return services;
        }

        // Configure options
        services.Configure<VaultaXOptions>(configuration.GetSection(VaultaXOptions.SectionName));

        // Register the Vault client (singleton for connection pooling)
        services.TryAddSingleton<IVaultClient, VaultClientWrapper>();

        // Register KV engine
        services.TryAddSingleton<IKeyValueEngine, KeyValueEngine>();

        // Register Transit engine with default mount point
        services.TryAddSingleton<ITransitEngine>(sp =>
        {
            var client = sp.GetRequiredService<IVaultClient>();
            var logger = sp.GetService<Microsoft.Extensions.Logging.ILogger<TransitEngine>>();
            return new TransitEngine(client, "transit", logger);
        });

        // Register PKI engine with default mount point
        services.TryAddSingleton<IPkiEngine>(sp =>
        {
            var client = sp.GetRequiredService<IVaultClient>();
            var logger = sp.GetService<Microsoft.Extensions.Logging.ILogger<PkiEngine>>();
            return new PkiEngine(client, "pki", logger);
        });

        // Register health check
        services.TryAddSingleton<VaultHealthCheck>();

        // Register background services if enabled
        if (options.TokenRenewal.Enabled)
        {
            services.AddHostedService<TokenRenewalService>();
        }

        if (options.Reload.Enabled)
        {
            services.AddHostedService<SecretChangeWatcherService>();
        }

        return services;
    }

    /// <summary>
    /// Adds a Transit engine with a custom mount point.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="mountPoint">The mount point for the Transit engine.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddVaultaXTransit(
        this IServiceCollection services,
        string mountPoint = "transit")
    {
        ArgumentNullException.ThrowIfNull(services);

        // Remove existing registration if any
        var descriptor = new ServiceDescriptor(
            typeof(ITransitEngine),
            sp =>
            {
                var client = sp.GetRequiredService<IVaultClient>();
                var logger = sp.GetService<Microsoft.Extensions.Logging.ILogger<TransitEngine>>();
                return new TransitEngine(client, mountPoint, logger);
            },
            ServiceLifetime.Singleton);

        services.Replace(descriptor);
        return services;
    }

    /// <summary>
    /// Adds a PKI engine with a custom mount point.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="mountPoint">The mount point for the PKI engine.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddVaultaXPki(
        this IServiceCollection services,
        string mountPoint = "pki")
    {
        ArgumentNullException.ThrowIfNull(services);

        // Remove existing registration if any
        var descriptor = new ServiceDescriptor(
            typeof(IPkiEngine),
            sp =>
            {
                var client = sp.GetRequiredService<IVaultClient>();
                var logger = sp.GetService<Microsoft.Extensions.Logging.ILogger<PkiEngine>>();
                return new PkiEngine(client, mountPoint, logger);
            },
            ServiceLifetime.Singleton);

        services.Replace(descriptor);
        return services;
    }
}
