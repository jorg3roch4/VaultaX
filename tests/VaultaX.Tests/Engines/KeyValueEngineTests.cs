using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Engines.KeyValue;
using VaultaX.Exceptions;
using VaultaX.Tests.Helpers;
using VaultSharp.V1.Commons;
using VaultSharp.V1.SecretsEngines.KeyValue.V1;
using VaultSharp.V1.SecretsEngines.KeyValue.V2;
using Xunit;

namespace VaultaX.Tests.Engines;

public class KeyValueEngineTests
{
    private readonly Mock<IVaultClient> _mockClient;
    private readonly Mock<VaultSharp.IVaultClient> _mockVaultSharp;
    private readonly Mock<IKeyValueSecretsEngineV2> _mockKvV2;
    private readonly Mock<IKeyValueSecretsEngineV1> _mockKvV1;

    public KeyValueEngineTests()
    {
        (_mockClient, _mockVaultSharp) = VaultMockHelper.CreateMockVaultClient();

        _mockKvV2 = new Mock<IKeyValueSecretsEngineV2>();
        _mockKvV1 = new Mock<IKeyValueSecretsEngineV1>();

        var mockSecrets = new Mock<VaultSharp.V1.SecretsEngines.ISecretsEngine>();
        var mockKv = new Mock<VaultSharp.V1.SecretsEngines.KeyValue.IKeyValueSecretsEngine>();
        mockKv.Setup(k => k.V2).Returns(_mockKvV2.Object);
        mockKv.Setup(k => k.V1).Returns(_mockKvV1.Object);
        mockSecrets.Setup(s => s.KeyValue).Returns(mockKv.Object);

        var mockV1 = new Mock<VaultSharp.V1.IVaultClientV1>();
        mockV1.Setup(v => v.Secrets).Returns(mockSecrets.Object);
        _mockVaultSharp.Setup(c => c.V1).Returns(mockV1.Object);
    }

    private KeyValueEngine CreateEngine(Action<VaultaXOptions>? configure = null)
    {
        var options = VaultMockHelper.CreateOptions(configure);
        return new KeyValueEngine(_mockClient.Object, options);
    }

    [Fact]
    public void Constructor_WithNullVaultClient_Throws()
    {
        // Arrange & Act & Assert
        var action = () => new KeyValueEngine(null!, VaultMockHelper.CreateDefaultOptions());
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void EngineType_KvV2_ReturnsKvV2()
    {
        // Arrange
        var engine = CreateEngine();

        // Act & Assert
        engine.EngineType.Should().Be("kv-v2");
    }

    [Fact]
    public void EngineType_KvV1_ReturnsKvV1()
    {
        // Arrange
        var engine = CreateEngine(o => o.KvVersion = 1);

        // Act & Assert
        engine.EngineType.Should().Be("kv-v1");
    }

    [Fact]
    public void MountPoint_ReturnsConfiguredValue()
    {
        // Arrange
        var engine = CreateEngine(o => o.MountPoint = "custom-kv");

        // Act & Assert
        engine.MountPoint.Should().Be("custom-kv");
    }

    [Fact]
    public async Task ReadAsync_KvV2_ReturnsData()
    {
        // Arrange
        var secretData = new Dictionary<string, object> { { "username", "admin" }, { "password", "secret" } };
        var innerData = new SecretData { Data = secretData };
        var secret = new Secret<SecretData> { Data = innerData };

        _mockKvV2
            .Setup(k => k.ReadSecretAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();

        // Act
        var result = await engine.ReadAsync("test/secret", cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().ContainKey("username");
        result["username"].Should().Be("admin");
    }

    [Fact]
    public async Task ReadAsync_KvV1_ReturnsData()
    {
        // Arrange
        var secretData = new Dictionary<string, object> { { "key1", "value1" } };
        var secret = new Secret<Dictionary<string, object>> { Data = secretData };

        _mockKvV1
            .Setup(k => k.ReadSecretAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine(o => o.KvVersion = 1);

        // Act
        var result = await engine.ReadAsync("test/secret", cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().ContainKey("key1");
    }

    [Fact]
    public async Task ReadAsync_WithVersion_KvV2_PassesVersion()
    {
        // Arrange
        var innerData = new SecretData { Data = new Dictionary<string, object>() };
        var secret = new Secret<SecretData> { Data = innerData };

        _mockKvV2
            .Setup(k => k.ReadSecretAsync(It.IsAny<string>(), 3, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();

        // Act
        await engine.ReadAsync("test/secret", version: 3, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        _mockKvV2.Verify(k => k.ReadSecretAsync(It.IsAny<string>(), 3, It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ReadAsync_On404_ThrowsVaultSecretNotFoundException()
    {
        // Arrange
        _mockKvV2
            .Setup(k => k.ReadSecretAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new VaultSharp.Core.VaultApiException(HttpStatusCode.NotFound, "not found"));

        var engine = CreateEngine();

        // Act & Assert
        var action = () => engine.ReadAsync("missing/path");
        await action.Should().ThrowAsync<VaultSecretNotFoundException>();
    }

    [Fact]
    public async Task ReadAsync_T_DeserializesCorrectly()
    {
        // Arrange
        var secretData = new Dictionary<string, object> { { "Name", "TestApp" }, { "Version", "1.0" } };
        var innerData = new SecretData { Data = secretData };
        var secret = new Secret<SecretData> { Data = innerData };

        _mockKvV2
            .Setup(k => k.ReadSecretAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();

        // Act
        var result = await engine.ReadAsync<TestSecretModel>("test/secret", cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Name.Should().Be("TestApp");
        result.Version.Should().Be("1.0");
    }

    [Fact]
    public async Task WriteAsync_KvV2_CallsWriteSecret()
    {
        // Arrange
        var data = new Dictionary<string, object?> { { "key", "value" } };
        var engine = CreateEngine();

        // Act
        await engine.WriteAsync("test/path", data, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        _mockKvV2.Verify(k => k.WriteSecretAsync(
            It.IsAny<string>(),
            It.IsAny<IDictionary<string, object?>>(),
            It.IsAny<int?>(),
            It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task WriteAsync_KvV1_CallsWriteSecret()
    {
        // Arrange
        var data = new Dictionary<string, object?> { { "key", "value" } };
        var engine = CreateEngine(o => o.KvVersion = 1);

        // Act
        await engine.WriteAsync("test/path", data, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        _mockKvV1.Verify(k => k.WriteSecretAsync(
            It.IsAny<string>(),
            It.IsAny<IDictionary<string, object>>(),
            It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task DeleteAsync_KvV2_CallsDeleteSecret()
    {
        // Arrange
        var engine = CreateEngine();

        // Act
        await engine.DeleteAsync("test/path", TestContext.Current.CancellationToken);

        // Assert
        _mockKvV2.Verify(k => k.DeleteSecretAsync(
            It.IsAny<string>(),
            It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task DeleteAsync_KvV1_CallsDeleteSecret()
    {
        // Arrange
        var engine = CreateEngine(o => o.KvVersion = 1);

        // Act
        await engine.DeleteAsync("test/path", TestContext.Current.CancellationToken);

        // Assert
        _mockKvV1.Verify(k => k.DeleteSecretAsync(
            It.IsAny<string>(),
            It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ListAsync_ReturnsKeys()
    {
        // Arrange
        var listInfo = new ListInfo { Keys = new List<string> { "secret1", "secret2/" } };
        var secret = new Secret<ListInfo> { Data = listInfo };

        _mockKvV2
            .Setup(k => k.ReadSecretPathsAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();

        // Act
        var result = await engine.ListAsync("test/", TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeEquivalentTo(new[] { "secret1", "secret2/" });
    }

    [Fact]
    public async Task ListAsync_On404_ReturnsEmpty()
    {
        // Arrange
        _mockKvV2
            .Setup(k => k.ReadSecretPathsAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new VaultSharp.Core.VaultApiException(HttpStatusCode.NotFound, "not found"));

        var engine = CreateEngine();

        // Act
        var result = await engine.ListAsync("missing/", TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task GetMetadataAsync_KvV1_ReturnsNull()
    {
        // Arrange
        var engine = CreateEngine(o => o.KvVersion = 1);

        // Act
        var result = await engine.GetMetadataAsync("test/path", TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetMetadataAsync_KvV2_ReturnsMetadata()
    {
        // Arrange
        var metadata = new FullSecretMetadata
        {
            CurrentVersion = 5,
            OldestVersion = 1,
            CreatedTime = "2024-01-01T00:00:00Z",
            UpdatedTime = "2024-06-15T12:00:00Z"
        };
        var secret = new Secret<FullSecretMetadata> { Data = metadata };

        _mockKvV2
            .Setup(k => k.ReadSecretMetadataAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();

        // Act
        var result = await engine.GetMetadataAsync("test/path", TestContext.Current.CancellationToken);

        // Assert
        result.Should().NotBeNull();
        result!.CurrentVersion.Should().Be(5);
        result.OldestVersion.Should().Be(1);
    }

    [Fact]
    public async Task GetMetadataAsync_KvV2_On404_ReturnsNull()
    {
        // Arrange
        _mockKvV2
            .Setup(k => k.ReadSecretMetadataAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new VaultSharp.Core.VaultApiException(HttpStatusCode.NotFound, "not found"));

        var engine = CreateEngine();

        // Act
        var result = await engine.GetMetadataAsync("test/path", TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeNull();
    }

    private class TestSecretModel
    {
        public string? Name { get; set; }
        public string? Version { get; set; }
    }
}
