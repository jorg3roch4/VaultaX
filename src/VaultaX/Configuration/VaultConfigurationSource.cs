using Microsoft.Extensions.Configuration;

namespace VaultaX.Configuration;

/// <summary>
/// Configuration source for loading secrets from HashiCorp Vault.
/// </summary>
public sealed class VaultConfigurationSource : IConfigurationSource
{
    private readonly VaultaXOptions _options;

    /// <summary>
    /// Creates a new Vault configuration source.
    /// </summary>
    /// <param name="options">The VaultaX options.</param>
    public VaultConfigurationSource(VaultaXOptions options)
    {
        _options = options ?? throw new System.ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        return new VaultConfigurationProvider(_options);
    }
}
