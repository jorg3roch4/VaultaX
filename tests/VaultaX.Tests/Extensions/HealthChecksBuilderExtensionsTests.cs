using System;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using VaultaX.Extensions;
using Xunit;

namespace VaultaX.Tests.Extensions;

public class HealthChecksBuilderExtensionsTests
{
    [Fact]
    public void AddVaultaX_RegistersHealthCheckWithDefaultName()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddHealthChecks();

        // Act
        builder.AddVaultaX();

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>();
        options.Value.Registrations.Should().Contain(r => r.Name == "vaultax");
    }

    [Fact]
    public void AddVaultaX_WithCustomName_RegistersWithCustomName()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddHealthChecks();

        // Act
        builder.AddVaultaX(name: "vault-primary");

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>();
        options.Value.Registrations.Should().Contain(r => r.Name == "vault-primary");
    }

    [Fact]
    public void AddVaultaX_WithAction_ConfiguresFromOptions()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddHealthChecks();

        // Act
        builder.AddVaultaX(options =>
        {
            options.Name = "custom-vault";
            options.FailureStatus = HealthStatus.Degraded;
            options.Tags = new[] { "vault", "secrets" };
        });

        // Assert
        var provider = services.BuildServiceProvider();
        var hcOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>();
        var registration = hcOptions.Value.Registrations.FirstOrDefault(r => r.Name == "custom-vault");
        registration.Should().NotBeNull();
        registration!.FailureStatus.Should().Be(HealthStatus.Degraded);
        registration.Tags.Should().Contain("vault");
    }

    [Fact]
    public async Task DisabledHealthCheck_ReturnsHealthy()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = services.AddHealthChecks();
        builder.AddVaultaX();
        var provider = services.BuildServiceProvider();

        // Act - The health check factory resolves VaultHealthCheck from DI;
        // since we didn't register it, it falls back to DisabledHealthCheck
        var hcOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>();
        var registration = hcOptions.Value.Registrations.First(r => r.Name == "vaultax");
        var healthCheck = registration.Factory(provider);

        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("disabled");
    }

    [Fact]
    public void VaultHealthCheckOptions_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var options = new VaultHealthCheckOptions();

        // Assert
        options.Name.Should().Be("vaultax");
        options.FailureStatus.Should().BeNull();
        options.Tags.Should().BeNull();
        options.Timeout.Should().BeNull();
    }
}
