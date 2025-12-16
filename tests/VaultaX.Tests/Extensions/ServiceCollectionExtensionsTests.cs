using System.Collections.Generic;
using System.IO;
using System.Linq;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Extensions;
using VaultaX.HealthChecks;
using Xunit;

namespace VaultaX.Tests.Extensions;

/// <summary>
/// Tests for ServiceCollectionExtensions.
/// </summary>
public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddVaultaX_WhenDisabled_DoesNotRegisterServices()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "false"
            })
            .Build();

        var services = new ServiceCollection();

        // Act
        services.AddVaultaX(configuration);

        // Assert
        var provider = services.BuildServiceProvider();
        var vaultClient = provider.GetService<IVaultClient>();
        vaultClient.Should().BeNull();
    }

    [Fact]
    public void AddVaultaX_WhenEnabled_RegistersVaultClient()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "true",
                ["VaultaX:Address"] = "http://localhost:8200",
                ["VaultaX:Authentication:Method"] = "Token",
                ["VaultaX:Authentication:Token"] = "VAULT_TOKEN"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddVaultaX(configuration);

        // Assert
        var descriptors = services.Where(d => d.ServiceType == typeof(IVaultClient)).ToList();
        descriptors.Should().HaveCount(1);
        descriptors[0].Lifetime.Should().Be(ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddVaultaX_WhenEnabled_RegistersKeyValueEngine()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "true",
                ["VaultaX:Address"] = "http://localhost:8200",
                ["VaultaX:Authentication:Method"] = "Token",
                ["VaultaX:Authentication:Token"] = "VAULT_TOKEN"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddVaultaX(configuration);

        // Assert
        var descriptors = services.Where(d => d.ServiceType == typeof(IKeyValueEngine)).ToList();
        descriptors.Should().HaveCount(1);
        descriptors[0].Lifetime.Should().Be(ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddVaultaX_WhenEnabled_RegistersTransitEngine()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "true",
                ["VaultaX:Address"] = "http://localhost:8200",
                ["VaultaX:Authentication:Method"] = "Token",
                ["VaultaX:Authentication:Token"] = "VAULT_TOKEN"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddVaultaX(configuration);

        // Assert
        var descriptors = services.Where(d => d.ServiceType == typeof(ITransitEngine)).ToList();
        descriptors.Should().HaveCount(1);
        descriptors[0].Lifetime.Should().Be(ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddVaultaX_WhenEnabled_RegistersPkiEngine()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "true",
                ["VaultaX:Address"] = "http://localhost:8200",
                ["VaultaX:Authentication:Method"] = "Token",
                ["VaultaX:Authentication:Token"] = "VAULT_TOKEN"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddVaultaX(configuration);

        // Assert
        var descriptors = services.Where(d => d.ServiceType == typeof(IPkiEngine)).ToList();
        descriptors.Should().HaveCount(1);
        descriptors[0].Lifetime.Should().Be(ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddVaultaX_WhenEnabled_RegistersHealthCheck()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "true",
                ["VaultaX:Address"] = "http://localhost:8200",
                ["VaultaX:Authentication:Method"] = "Token",
                ["VaultaX:Authentication:Token"] = "VAULT_TOKEN"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddVaultaX(configuration);

        // Assert
        var descriptors = services.Where(d => d.ServiceType == typeof(VaultHealthCheck)).ToList();
        descriptors.Should().HaveCount(1);
    }

    [Fact]
    public void AddVaultaX_ConfiguresOptions()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "true",
                ["VaultaX:Address"] = "http://localhost:8200",
                ["VaultaX:MountPoint"] = "kv",
                ["VaultaX:KvVersion"] = "2",
                ["VaultaX:BasePath"] = "production",
                ["VaultaX:Authentication:Method"] = "AppRole",
                ["VaultaX:Authentication:RoleId"] = "my-role",
                ["VaultaX:Authentication:SecretId"] = "VAULT_SECRET_ID"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddVaultaX(configuration);

        // Act
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<VaultaXOptions>>();

        // Assert
        options.Value.Enabled.Should().BeTrue();
        options.Value.Address.Should().Be("http://localhost:8200");
        options.Value.MountPoint.Should().Be("kv");
        options.Value.KvVersion.Should().Be(2);
        options.Value.BasePath.Should().Be("production");
        options.Value.Authentication.Method.Should().Be("AppRole");
        options.Value.Authentication.RoleId.Should().Be("my-role");
        options.Value.Authentication.SecretId.Should().Be("VAULT_SECRET_ID");
    }

    [Fact]
    public void AddVaultaXTransit_ReplacesExistingRegistration()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "true",
                ["VaultaX:Address"] = "http://localhost:8200",
                ["VaultaX:Authentication:Method"] = "Token",
                ["VaultaX:Authentication:Token"] = "VAULT_TOKEN"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddVaultaX(configuration);

        // Act
        services.AddVaultaXTransit("custom-transit");

        // Assert
        var descriptors = services.Where(d => d.ServiceType == typeof(ITransitEngine)).ToList();
        descriptors.Should().HaveCount(1);
    }

    [Fact]
    public void AddVaultaXPki_ReplacesExistingRegistration()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultaX:Enabled"] = "true",
                ["VaultaX:Address"] = "http://localhost:8200",
                ["VaultaX:Authentication:Method"] = "Token",
                ["VaultaX:Authentication:Token"] = "VAULT_TOKEN"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddVaultaX(configuration);

        // Act
        services.AddVaultaXPki("custom-pki");

        // Assert
        var descriptors = services.Where(d => d.ServiceType == typeof(IPkiEngine)).ToList();
        descriptors.Should().HaveCount(1);
    }

    [Fact]
    public void AddVaultaX_WhenNotConfigured_DoesNotRegisterServices()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        var services = new ServiceCollection();

        // Act
        services.AddVaultaX(configuration);

        // Assert
        var provider = services.BuildServiceProvider();
        var vaultClient = provider.GetService<IVaultClient>();
        vaultClient.Should().BeNull();
    }
}
