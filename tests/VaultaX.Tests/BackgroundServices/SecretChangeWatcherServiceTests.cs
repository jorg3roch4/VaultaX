using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using VaultaX.Abstractions;
using VaultaX.BackgroundServices;
using VaultaX.Tests.Helpers;
using Xunit;

namespace VaultaX.Tests.BackgroundServices;

public class SecretChangeWatcherServiceTests
{
    private readonly Mock<IVaultClient> _mockClient;
    private readonly Mock<IConfiguration> _mockConfig;
    private readonly Mock<ILogger<SecretChangeWatcherService>> _mockLogger;

    public SecretChangeWatcherServiceTests()
    {
        (_mockClient, _) = VaultMockHelper.CreateMockVaultClient();
        _mockConfig = new Mock<IConfiguration>();
        _mockLogger = new Mock<ILogger<SecretChangeWatcherService>>();
    }

    [Fact]
    public void Constructor_WithNullVaultClient_Throws()
    {
        // Act & Assert
        var options = VaultMockHelper.CreateDefaultOptions();
        var action = () => new SecretChangeWatcherService(null!, _mockConfig.Object, options, _mockLogger.Object);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullConfiguration_Throws()
    {
        // Act & Assert
        var options = VaultMockHelper.CreateDefaultOptions();
        var action = () => new SecretChangeWatcherService(_mockClient.Object, null!, options, _mockLogger.Object);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullOptions_Throws()
    {
        // Act & Assert
        var action = () => new SecretChangeWatcherService(_mockClient.Object, _mockConfig.Object, null!, _mockLogger.Object);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullLogger_Throws()
    {
        // Act & Assert
        var options = VaultMockHelper.CreateDefaultOptions();
        var action = () => new SecretChangeWatcherService(_mockClient.Object, _mockConfig.Object, options, null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task ExecuteAsync_WhenDisabled_ReturnsImmediately()
    {
        // Arrange
        var options = VaultMockHelper.CreateOptions(o => o.Enabled = false);
        var service = new SecretChangeWatcherService(_mockClient.Object, _mockConfig.Object, options, _mockLogger.Object);

        // Act
        await service.StartAsync(TestContext.Current.CancellationToken);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        await service.StopAsync(TestContext.Current.CancellationToken);

        // Assert - should not call GetUnderlyingClient
        _mockClient.Verify(c => c.GetUnderlyingClient(), Times.Never);
    }

    [Fact]
    public async Task ExecuteAsync_WhenReloadDisabled_ReturnsImmediately()
    {
        // Arrange
        var options = VaultMockHelper.CreateOptions(o =>
        {
            o.Enabled = true;
            o.Reload.Enabled = false;
        });
        var service = new SecretChangeWatcherService(_mockClient.Object, _mockConfig.Object, options, _mockLogger.Object);

        // Act
        await service.StartAsync(TestContext.Current.CancellationToken);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        await service.StopAsync(TestContext.Current.CancellationToken);

        // Assert
        _mockClient.Verify(c => c.GetUnderlyingClient(), Times.Never);
    }

    [Fact]
    public async Task ExecuteAsync_WhenKvV1_ReturnsImmediately()
    {
        // Arrange
        var options = VaultMockHelper.CreateOptions(o =>
        {
            o.Enabled = true;
            o.Reload.Enabled = true;
            o.KvVersion = 1;
        });
        var service = new SecretChangeWatcherService(_mockClient.Object, _mockConfig.Object, options, _mockLogger.Object);

        // Act
        await service.StartAsync(TestContext.Current.CancellationToken);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        await service.StopAsync(TestContext.Current.CancellationToken);

        // Assert
        _mockClient.Verify(c => c.GetUnderlyingClient(), Times.Never);
    }
}
