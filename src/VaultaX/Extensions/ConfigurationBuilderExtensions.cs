using System;
using Microsoft.Extensions.Configuration;
using VaultaX.Configuration;

namespace VaultaX.Extensions;

/// <summary>
/// Extension methods for adding VaultaX as a configuration source.
/// </summary>
public static class ConfigurationBuilderExtensions
{
    /// <summary>
    /// Adds VaultaX as a configuration source.
    /// Reads configuration from the "VaultaX" section of existing configuration.
    /// If VaultaX:Enabled is false, this method does nothing (transparent).
    /// </summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="sectionName">The configuration section name (default: "VaultaX").</param>
    /// <returns>The configuration builder for chaining.</returns>
    /// <remarks>
    /// Call this method after adding appsettings.json but before building configuration.
    /// Vault secrets will override values from appsettings with the same keys.
    ///
    /// Example:
    /// <code>
    /// builder.Configuration.AddVaultaX();
    /// </code>
    /// </remarks>
    public static IConfigurationBuilder AddVaultaX(
        this IConfigurationBuilder builder,
        string sectionName = VaultaXOptions.SectionName)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Build temporary configuration to read VaultaX options
        var tempConfig = builder.Build();
        var options = tempConfig.GetSection(sectionName).Get<VaultaXOptions>();

        // If not enabled or not configured, do nothing (transparent)
        if (options == null || !options.Enabled)
        {
            return builder;
        }

        // Validate configuration
        VaultaXOptionsValidator.Validate(options);

        // Add Vault as a configuration source
        return builder.Add(new VaultConfigurationSource(options));
    }

    /// <summary>
    /// Adds VaultaX as a configuration source with programmatic configuration.
    /// </summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="configure">Action to configure VaultaX options.</param>
    /// <returns>The configuration builder for chaining.</returns>
    /// <remarks>
    /// Use this overload when you need to configure VaultaX programmatically
    /// instead of using appsettings.json.
    ///
    /// Example:
    /// <code>
    /// builder.Configuration.AddVaultaX(options =>
    /// {
    ///     options.Enabled = true;
    ///     options.Address = "https://vault.company.com:8200";
    ///     options.Authentication.Method = "AppRole";
    ///     options.Authentication.RoleId = "my-role-id";
    ///     options.Mappings.Add(new SecretMappingOptions
    ///     {
    ///         SecretPath = "database",
    ///         Bindings = new() { { "connectionString", "ConnectionStrings:DefaultConnection" } }
    ///     });
    /// });
    /// </code>
    /// </remarks>
    public static IConfigurationBuilder AddVaultaX(
        this IConfigurationBuilder builder,
        Action<VaultaXOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new VaultaXOptions();
        configure(options);

        // If not enabled, do nothing
        if (!options.Enabled)
        {
            return builder;
        }

        // Validate configuration
        VaultaXOptionsValidator.Validate(options);

        // Add Vault as a configuration source
        return builder.Add(new VaultConfigurationSource(options));
    }
}
