using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Moq;
using VaultaX.Abstractions;
using VaultaX.HealthChecks;
using VaultaX.Tests.Helpers;
using Xunit;
using HealthStatus = Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus;
using VaultHealthStatus = VaultSharp.V1.SystemBackend.HealthStatus;

namespace VaultaX.Tests.HealthChecks;

public class VaultHealthCheckTests
{
    private readonly Mock<IVaultClient> _mockClient;
    private readonly Mock<VaultSharp.IVaultClient> _mockVaultSharp;
    private readonly Mock<VaultSharp.V1.SystemBackend.ISystemBackend> _mockSystem;

    public VaultHealthCheckTests()
    {
        (_mockClient, _mockVaultSharp) = VaultMockHelper.CreateMockVaultClient();

        _mockSystem = new Mock<VaultSharp.V1.SystemBackend.ISystemBackend>();

        var mockV1 = new Mock<VaultSharp.V1.IVaultClientV1>();
        mockV1.Setup(v => v.System).Returns(_mockSystem.Object);
        _mockVaultSharp.Setup(c => c.V1).Returns(mockV1.Object);
    }

    private VaultHealthCheck CreateHealthCheck(Action<VaultaX.Configuration.VaultaXOptions>? configure = null)
    {
        var options = VaultMockHelper.CreateOptions(configure);
        return new VaultHealthCheck(_mockClient.Object, options);
    }

    private void SetupHealthyVault()
    {
        var healthStatus = new VaultHealthStatus
        {
            Initialized = true,
            Sealed = false,
            Standby = false,
            ClusterName = "test-cluster",
            Version = "1.15.0"
        };

        _mockSystem
            .Setup(s => s.GetHealthStatusAsync())
            .ReturnsAsync(healthStatus);
    }

    [Fact]
    public async Task CheckHealthAsync_WhenDisabled_ReturnsHealthy()
    {
        // Arrange
        var healthCheck = CreateHealthCheck(o => o.Enabled = false);

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("disabled");
        result.Data.Should().ContainKey("enabled");
        result.Data!["enabled"].Should().Be(false);
    }

    [Fact]
    public async Task CheckHealthAsync_WhenSealed_ReturnsUnhealthy()
    {
        // Arrange
        _mockClient.Setup(c => c.IsAuthenticated).Returns(true);
        _mockSystem
            .Setup(s => s.GetHealthStatusAsync())
            .ReturnsAsync(new VaultHealthStatus { Initialized = true, Sealed = true, Standby = false });

        var healthCheck = CreateHealthCheck();

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Contain("sealed");
    }

    [Fact]
    public async Task CheckHealthAsync_WhenNotInitialized_ReturnsUnhealthy()
    {
        // Arrange
        _mockClient.Setup(c => c.IsAuthenticated).Returns(true);
        _mockSystem
            .Setup(s => s.GetHealthStatusAsync())
            .ReturnsAsync(new VaultHealthStatus { Initialized = false, Sealed = false, Standby = false });

        var healthCheck = CreateHealthCheck();

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Contain("not initialized");
    }

    [Fact]
    public async Task CheckHealthAsync_WhenStandby_ReturnsDegraded()
    {
        // Arrange
        _mockClient.Setup(c => c.IsAuthenticated).Returns(true);
        _mockSystem
            .Setup(s => s.GetHealthStatusAsync())
            .ReturnsAsync(new VaultHealthStatus { Initialized = true, Sealed = false, Standby = true });

        var healthCheck = CreateHealthCheck();

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("standby");
    }

    [Fact]
    public async Task CheckHealthAsync_WhenNotAuthenticated_ReturnsDegraded()
    {
        // Arrange
        _mockClient.Setup(c => c.IsAuthenticated).Returns(false);
        _mockClient.Setup(c => c.AuthenticateAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("auth failed"));
        _mockSystem
            .Setup(s => s.GetHealthStatusAsync())
            .ReturnsAsync(new VaultHealthStatus { Initialized = true, Sealed = false, Standby = false });

        var healthCheck = CreateHealthCheck();

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("Not authenticated");
    }

    [Fact]
    public async Task CheckHealthAsync_WhenTokenNearExpiry_ReturnsDegraded()
    {
        // Arrange
        _mockClient.Setup(c => c.IsAuthenticated).Returns(true);
        _mockClient.Setup(c => c.TokenTimeToLive).Returns(TimeSpan.FromMinutes(2));
        SetupHealthyVault();

        var healthCheck = CreateHealthCheck();

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("expires");
    }

    [Fact]
    public async Task CheckHealthAsync_WhenEverythingFine_ReturnsHealthy()
    {
        // Arrange
        _mockClient.Setup(c => c.IsAuthenticated).Returns(true);
        _mockClient.Setup(c => c.TokenTimeToLive).Returns(TimeSpan.FromHours(1));
        _mockClient.Setup(c => c.IsTokenRenewable).Returns(true);
        SetupHealthyVault();

        var healthCheck = CreateHealthCheck();

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Data.Should().ContainKey("authenticated");
        result.Data!["authenticated"].Should().Be(true);
    }

    [Fact]
    public async Task CheckHealthAsync_OnVaultApiException_ReturnsUnhealthy()
    {
        // Arrange
        _mockClient.Setup(c => c.IsAuthenticated).Returns(true);
        _mockSystem
            .Setup(s => s.GetHealthStatusAsync())
            .ThrowsAsync(new VaultSharp.Core.VaultApiException(HttpStatusCode.InternalServerError, "vault error"));

        var healthCheck = CreateHealthCheck();

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Contain("Vault API error");
    }

    [Fact]
    public async Task CheckHealthAsync_OnGeneralException_ReturnsUnhealthy()
    {
        // Arrange
        _mockClient.Setup(c => c.IsAuthenticated).Returns(true);
        _mockSystem
            .Setup(s => s.GetHealthStatusAsync())
            .ThrowsAsync(new Exception("connection refused"));

        var healthCheck = CreateHealthCheck();

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Contain("Health check failed");
    }
}
