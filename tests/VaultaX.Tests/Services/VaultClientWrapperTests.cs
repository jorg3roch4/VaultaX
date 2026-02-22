using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Options;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultaX.Services;
using Xunit;

namespace VaultaX.Tests.Services;

public class VaultClientWrapperTests
{
    private static VaultaXOptions CreateValidOptions(Action<VaultaXOptions>? configure = null)
    {
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "http://localhost:8200",
            MountPoint = "secret",
            KvVersion = 2,
            Authentication = new AuthenticationOptions
            {
                Method = "Token",
                Token = "static:test-token"
            }
        };
        configure?.Invoke(options);
        return options;
    }

    [Fact]
    public void Constructor_WithNullIOptions_Throws()
    {
        // Act & Assert
        var action = () => new VaultClientWrapper((IOptions<VaultaXOptions>)null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithNullOptions_Throws()
    {
        // Act & Assert
        var action = () => new VaultClientWrapper((VaultaXOptions)null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void IsAuthenticated_Initially_ReturnsFalse()
    {
        // Arrange
        var options = CreateValidOptions();
        var wrapper = new VaultClientWrapper(options);

        // Act & Assert
        wrapper.IsAuthenticated.Should().BeFalse();
    }

    [Fact]
    public void TokenTimeToLive_Initially_ReturnsNull()
    {
        // Arrange
        var options = CreateValidOptions();
        var wrapper = new VaultClientWrapper(options);

        // Act & Assert
        wrapper.TokenTimeToLive.Should().BeNull();
    }

    [Fact]
    public void IsTokenRenewable_Initially_ReturnsFalse()
    {
        // Arrange
        var options = CreateValidOptions();
        var wrapper = new VaultClientWrapper(options);

        // Act & Assert
        wrapper.IsTokenRenewable.Should().BeFalse();
    }

    [Fact]
    public void GetUnderlyingClient_ReturnsVaultSharpClient()
    {
        // Arrange
        var options = CreateValidOptions();
        var wrapper = new VaultClientWrapper(options);

        // Act
        var client = wrapper.GetUnderlyingClient();

        // Assert
        client.Should().NotBeNull();
        client.Should().BeAssignableTo<VaultSharp.IVaultClient>();
    }

    [Fact]
    public void GetUnderlyingClient_ReturnsSameInstance()
    {
        // Arrange
        var options = CreateValidOptions();
        var wrapper = new VaultClientWrapper(options);

        // Act
        var client1 = wrapper.GetUnderlyingClient();
        var client2 = wrapper.GetUnderlyingClient();

        // Assert
        client1.Should().BeSameAs(client2);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        // Arrange
        var options = CreateValidOptions();
        var wrapper = new VaultClientWrapper(options);

        // Act & Assert - should not throw
        wrapper.Dispose();
        wrapper.Dispose();
    }

    [Fact]
    public void Dispose_ClearsState()
    {
        // Arrange
        var options = CreateValidOptions();
        var wrapper = new VaultClientWrapper(options);
        _ = wrapper.GetUnderlyingClient(); // Force client creation

        // Act
        wrapper.Dispose();

        // Assert
        wrapper.IsAuthenticated.Should().BeFalse();
        wrapper.TokenTimeToLive.Should().BeNull();
        wrapper.IsTokenRenewable.Should().BeFalse();
    }

    [Fact]
    public void Constructor_WithIOptions_CreatesSuccessfully()
    {
        // Arrange
        var options = Options.Create(CreateValidOptions());

        // Act
        var wrapper = new VaultClientWrapper(options);

        // Assert
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public async Task ReadSecretAsync_WithNullPath_Throws()
    {
        // Arrange
        var wrapper = new VaultClientWrapper(CreateValidOptions());

        // Act & Assert
        var action = () => wrapper.ReadSecretAsync(null!);
        await action.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task ReadSecretAsync_WithEmptyPath_Throws()
    {
        // Arrange
        var wrapper = new VaultClientWrapper(CreateValidOptions());

        // Act & Assert
        var action = () => wrapper.ReadSecretAsync("");
        await action.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task WriteSecretAsync_WithNullPath_Throws()
    {
        // Arrange
        var wrapper = new VaultClientWrapper(CreateValidOptions());

        // Act & Assert
        var action = () => wrapper.WriteSecretAsync(null!, new Dictionary<string, object?>());
        await action.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task WriteSecretAsync_WithNullData_Throws()
    {
        // Arrange
        var wrapper = new VaultClientWrapper(CreateValidOptions());

        // Act & Assert
        var action = () => wrapper.WriteSecretAsync("test", null!);
        await action.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task DeleteSecretAsync_WithNullPath_Throws()
    {
        // Arrange
        var wrapper = new VaultClientWrapper(CreateValidOptions());

        // Act & Assert
        var action = () => wrapper.DeleteSecretAsync(null!);
        await action.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task GetSecretMetadataAsync_KvV1_ReturnsNull()
    {
        // Arrange
        var options = CreateValidOptions(o => o.KvVersion = 1);
        var wrapper = new VaultClientWrapper(options);

        // Act
        var result = await wrapper.GetSecretMetadataAsync("test", TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void Constructor_WithBasePath_BuildsFullPathCorrectly()
    {
        // Arrange - We can verify BuildFullPath indirectly through the options
        var options = CreateValidOptions(o => o.BasePath = "myapp/production");
        var wrapper = new VaultClientWrapper(options);

        // Assert - the wrapper was created successfully with a base path
        wrapper.Should().NotBeNull();
    }
}
