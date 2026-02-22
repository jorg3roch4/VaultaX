using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using VaultaX.Abstractions;
using VaultaX.BackgroundServices;
using VaultaX.Tests.Helpers;
using Xunit;

namespace VaultaX.Tests.BackgroundServices;

public class TokenRenewalServiceTests
{
    private readonly Mock<IVaultClient> _mockClient;
    private readonly Mock<ILogger<TokenRenewalService>> _mockLogger;

    public TokenRenewalServiceTests()
    {
        (_mockClient, _) = VaultMockHelper.CreateMockVaultClient();
        _mockLogger = new Mock<ILogger<TokenRenewalService>>();
    }

    [Fact]
    public void Constructor_WithNullVaultClient_Throws()
    {
        // Act & Assert
        var options = VaultMockHelper.CreateDefaultOptions();
        var action = () => new TokenRenewalService(null!, options, _mockLogger.Object);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullOptions_Throws()
    {
        // Act & Assert
        var action = () => new TokenRenewalService(_mockClient.Object, null!, _mockLogger.Object);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullLogger_Throws()
    {
        // Act & Assert
        var options = VaultMockHelper.CreateDefaultOptions();
        var action = () => new TokenRenewalService(_mockClient.Object, options, null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task ExecuteAsync_WhenDisabled_ReturnsImmediately()
    {
        // Arrange
        var options = VaultMockHelper.CreateOptions(o => o.Enabled = false);
        var service = new TokenRenewalService(_mockClient.Object, options, _mockLogger.Object);

        // Act
        await service.StartAsync(TestContext.Current.CancellationToken);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        await service.StopAsync(TestContext.Current.CancellationToken);

        // Assert - should not call RenewTokenAsync
        _mockClient.Verify(c => c.RenewTokenAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ExecuteAsync_WhenTokenRenewalDisabled_ReturnsImmediately()
    {
        // Arrange
        var options = VaultMockHelper.CreateOptions(o =>
        {
            o.Enabled = true;
            o.TokenRenewal.Enabled = false;
        });
        var service = new TokenRenewalService(_mockClient.Object, options, _mockLogger.Object);

        // Act
        await service.StartAsync(TestContext.Current.CancellationToken);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        await service.StopAsync(TestContext.Current.CancellationToken);

        // Assert
        _mockClient.Verify(c => c.RenewTokenAsync(It.IsAny<CancellationToken>()), Times.Never);
    }
}
