using System;
using System.Collections.Generic;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using VaultaX.Extensions;
using Xunit;

namespace VaultaX.Tests.Extensions;

public class ConfigurationBuilderExtensionsTests
{
    [Fact]
    public void AddVaultaX_WhenNotConfigured_DoesNothing()
    {
        // Arrange
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>());

        // Act
        var result = builder.AddVaultaX();

        // Assert
        result.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddVaultaX_WhenEnabledIsFalse_DoesNothing()
    {
        // Arrange
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "false"
            });

        // Act
        var result = builder.AddVaultaX();

        // Assert
        result.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddVaultaX_ThrowsOnNullBuilder()
    {
        // Arrange
        IConfigurationBuilder builder = null!;

        // Act & Assert
        var action = () => builder.AddVaultaX();
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddVaultaX_WithAction_WhenEnabledIsFalse_DoesNothing()
    {
        // Arrange
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>());

        // Act
        var result = builder.AddVaultaX(options =>
        {
            options.Enabled = false;
        });

        // Assert
        result.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddVaultaX_WithAction_ThrowsOnNullBuilder()
    {
        // Arrange
        IConfigurationBuilder builder = null!;

        // Act & Assert
        var action = () => builder.AddVaultaX(o => { });
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddVaultaX_WithAction_ThrowsOnNullAction()
    {
        // Arrange
        var builder = new ConfigurationBuilder();

        // Act & Assert
        var action = () => builder.AddVaultaX((Action<VaultaX.Configuration.VaultaXOptions>)null!);
        action.Should().Throw<ArgumentNullException>();
    }
}
