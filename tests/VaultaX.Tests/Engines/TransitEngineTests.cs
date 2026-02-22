using System;
using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using VaultaX.Abstractions;
using VaultaX.Engines.Transit;
using VaultaX.Exceptions;
using VaultaX.Tests.Helpers;
using VaultSharp.V1.Commons;
using VaultSharp.V1.SecretsEngines.Transit;
using Xunit;

namespace VaultaX.Tests.Engines;

public class TransitEngineTests
{
    private readonly Mock<IVaultClient> _mockClient;
    private readonly Mock<VaultSharp.IVaultClient> _mockVaultSharp;
    private readonly Mock<ITransitSecretsEngine> _mockTransit;

    public TransitEngineTests()
    {
        (_mockClient, _mockVaultSharp) = VaultMockHelper.CreateMockVaultClient();

        _mockTransit = new Mock<ITransitSecretsEngine>();

        var mockSecrets = new Mock<VaultSharp.V1.SecretsEngines.ISecretsEngine>();
        mockSecrets.Setup(s => s.Transit).Returns(_mockTransit.Object);

        var mockV1 = new Mock<VaultSharp.V1.IVaultClientV1>();
        mockV1.Setup(v => v.Secrets).Returns(mockSecrets.Object);
        _mockVaultSharp.Setup(c => c.V1).Returns(mockV1.Object);
    }

    private TransitEngine CreateEngine(string mountPoint = "transit")
        => new(_mockClient.Object, mountPoint);

    [Fact]
    public void Constructor_WithNullVaultClient_Throws()
    {
        // Act & Assert
        var action = () => new TransitEngine(null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void EngineType_ReturnsTransit()
    {
        // Arrange
        var engine = CreateEngine();

        // Act & Assert
        engine.EngineType.Should().Be("transit");
    }

    [Fact]
    public void MountPoint_ReturnsConfiguredValue()
    {
        // Arrange
        var engine = CreateEngine("custom-transit");

        // Act & Assert
        engine.MountPoint.Should().Be("custom-transit");
    }

    [Fact]
    public async Task EncryptAsync_ReturnsEncryptedCiphertext()
    {
        // Arrange
        var encryptResult = new Secret<EncryptionResponse>
        {
            Data = new EncryptionResponse { CipherText = "vault:v1:encrypted" }
        };

        _mockTransit
            .Setup(t => t.EncryptAsync(
                It.IsAny<string>(),
                It.IsAny<EncryptRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(encryptResult);

        var engine = CreateEngine();

        // Act
        var result = await engine.EncryptAsync("my-key", new byte[] { 1, 2, 3 }, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("vault:v1:encrypted");
    }

    [Fact]
    public async Task EncryptAsync_WithContext_PassesContext()
    {
        // Arrange
        var encryptResult = new Secret<EncryptionResponse>
        {
            Data = new EncryptionResponse { CipherText = "vault:v1:encrypted" }
        };

        _mockTransit
            .Setup(t => t.EncryptAsync(
                It.IsAny<string>(),
                It.Is<EncryptRequestOptions>(o => o.Base64EncodedContext != null),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(encryptResult);

        var engine = CreateEngine();

        // Act
        var result = await engine.EncryptAsync("my-key", new byte[] { 1, 2, 3 }, context: new byte[] { 4, 5, 6 }, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("vault:v1:encrypted");
    }

    [Fact]
    public async Task EncryptAsync_OnError_ThrowsVaultTransitException()
    {
        // Arrange
        _mockTransit
            .Setup(t => t.EncryptAsync(
                It.IsAny<string>(),
                It.IsAny<EncryptRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ThrowsAsync(new Exception("encrypt error"));

        var engine = CreateEngine();

        // Act & Assert
        var action = () => engine.EncryptAsync("my-key", new byte[] { 1 });
        await action.Should().ThrowAsync<VaultTransitException>()
            .WithMessage("*Encryption failed*");
    }

    [Fact]
    public async Task DecryptAsync_ReturnsPlaintextBytes()
    {
        // Arrange
        var plaintext = Convert.ToBase64String(new byte[] { 72, 101, 108, 108, 111 });
        var decryptResult = new Secret<DecryptionResponse>
        {
            Data = new DecryptionResponse { Base64EncodedPlainText = plaintext }
        };

        _mockTransit
            .Setup(t => t.DecryptAsync(
                It.IsAny<string>(),
                It.IsAny<DecryptRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(decryptResult);

        var engine = CreateEngine();

        // Act
        var result = await engine.DecryptAsync("my-key", "vault:v1:encrypted", cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeEquivalentTo(new byte[] { 72, 101, 108, 108, 111 });
    }

    [Fact]
    public async Task DecryptAsync_OnError_ThrowsVaultTransitException()
    {
        // Arrange
        _mockTransit
            .Setup(t => t.DecryptAsync(
                It.IsAny<string>(),
                It.IsAny<DecryptRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ThrowsAsync(new Exception("decrypt error"));

        var engine = CreateEngine();

        // Act & Assert
        var action = () => engine.DecryptAsync("my-key", "vault:v1:cipher");
        await action.Should().ThrowAsync<VaultTransitException>()
            .WithMessage("*Decryption failed*");
    }

    [Fact]
    public async Task SignAsync_ReturnsSignResponse()
    {
        // Arrange
        var signResult = new Secret<SigningResponse>
        {
            Data = new SigningResponse { Signature = "vault:v1:sig123", KeyVersion = 1 }
        };

        _mockTransit
            .Setup(t => t.SignDataAsync(
                It.IsAny<string>(),
                It.IsAny<SignRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(signResult);

        var engine = CreateEngine();
        var request = new TransitSignRequest
        {
            KeyName = "sign-key",
            Data = new byte[] { 1, 2, 3 }
        };

        // Act
        var result = await engine.SignAsync(request, TestContext.Current.CancellationToken);

        // Assert
        result.Signature.Should().Be("vault:v1:sig123");
        result.KeyVersion.Should().Be(1);
    }

    [Fact]
    public async Task SignAsync_WithMarshalingAlgorithm_PassesOption()
    {
        // Arrange
        var signResult = new Secret<SigningResponse>
        {
            Data = new SigningResponse { Signature = "vault:v1:sig", KeyVersion = 1 }
        };

        _mockTransit
            .Setup(t => t.SignDataAsync(
                It.IsAny<string>(),
                It.Is<SignRequestOptions>(o => o.MarshalingAlgorithm == MarshalingAlgorithm.jws),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(signResult);

        var engine = CreateEngine();
        var request = new TransitSignRequest
        {
            KeyName = "sign-key",
            Data = new byte[] { 1 },
            MarshalingAlgorithm = TransitMarshalingAlgorithm.Jws
        };

        // Act
        var result = await engine.SignAsync(request, TestContext.Current.CancellationToken);

        // Assert
        result.Should().NotBeNull();
    }

    [Fact]
    public async Task VerifyAsync_ReturnsValidOrInvalid()
    {
        // Arrange
        var verifyResult = new Secret<VerifyResponse>
        {
            Data = new VerifyResponse { Valid = true }
        };

        _mockTransit
            .Setup(t => t.VerifySignedDataAsync(
                It.IsAny<string>(),
                It.IsAny<VerifyRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(verifyResult);

        var engine = CreateEngine();
        var request = new TransitVerifyRequest
        {
            KeyName = "sign-key",
            Data = new byte[] { 1, 2, 3 },
            Signature = "vault:v1:sig"
        };

        // Act
        var result = await engine.VerifyAsync(request, TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task HashAsync_ReturnsHash()
    {
        // Arrange
        var hashResult = new Secret<HashResponse>
        {
            Data = new HashResponse { HashSum = "sha256:abc123" }
        };

        _mockTransit
            .Setup(t => t.HashDataAsync(
                It.IsAny<HashRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(hashResult);

        var engine = CreateEngine();

        // Act
        var result = await engine.HashAsync(new byte[] { 1, 2, 3 }, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("sha256:abc123");
    }

    [Fact]
    public async Task HmacAsync_ReturnsHmac()
    {
        // Arrange
        var hmacResult = new Secret<HmacResponse>
        {
            Data = new HmacResponse { Hmac = "vault:v1:hmac123" }
        };

        _mockTransit
            .Setup(t => t.GenerateHmacAsync(
                It.IsAny<string>(),
                It.IsAny<HmacRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(hmacResult);

        var engine = CreateEngine();

        // Act
        var result = await engine.HmacAsync("my-key", new byte[] { 1, 2, 3 }, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("vault:v1:hmac123");
    }

    [Fact]
    public async Task GenerateRandomBytesAsync_ReturnsRandomBytes()
    {
        // Arrange
        var randomResult = new Secret<RandomBytesResponse>
        {
            Data = new RandomBytesResponse { EncodedRandomBytes = "dGVzdA==" }
        };

        _mockTransit
            .Setup(t => t.GenerateRandomBytesAsync(
                It.IsAny<RandomBytesRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(randomResult);

        var engine = CreateEngine();

        // Act
        var result = await engine.GenerateRandomBytesAsync(32, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("dGVzdA==");
    }

    [Fact]
    public void GenerateRandomBytesAsync_WithZeroByteCount_Throws()
    {
        // Arrange
        var engine = CreateEngine();

        // Act & Assert
        var action = () => engine.GenerateRandomBytesAsync(0);
        action.Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void GenerateRandomBytesAsync_WithNegativeByteCount_Throws()
    {
        // Arrange
        var engine = CreateEngine();

        // Act & Assert
        var action = () => engine.GenerateRandomBytesAsync(-1);
        action.Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    [Fact]
    public async Task GetKeyInfoAsync_ReturnsKeyInfo()
    {
        // Arrange
        var keyResult = new Secret<EncryptionKeyInfo>
        {
            Data = new EncryptionKeyInfo
            {
                Name = "my-key",
                Type = TransitKeyType.aes256_gcm96,
                LatestVersion = 3,
                MinimumDecryptionVersion = 1,
                MinimumEncryptionVersion = 2,
                SupportsDerivation = true,
                Exportable = false,
                DeletionAllowed = false
            }
        };

        _mockTransit
            .Setup(t => t.ReadEncryptionKeyAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(keyResult);

        var engine = CreateEngine();

        // Act
        var result = await engine.GetKeyInfoAsync("my-key", TestContext.Current.CancellationToken);

        // Assert
        result.Should().NotBeNull();
        result!.Name.Should().Be("my-key");
        result.LatestVersion.Should().Be(3);
        result.MinDecryptionVersion.Should().Be(1);
        result.MinEncryptionVersion.Should().Be(2);
        result.SupportsDrivation.Should().BeTrue();
    }

    [Fact]
    public async Task GetKeyInfoAsync_On404_ReturnsNull()
    {
        // Arrange
        _mockTransit
            .Setup(t => t.ReadEncryptionKeyAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ThrowsAsync(new VaultSharp.Core.VaultApiException(HttpStatusCode.NotFound, "not found"));

        var engine = CreateEngine();

        // Act
        var result = await engine.GetKeyInfoAsync("missing-key", TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task RewrapAsync_ReturnsRewrappedCiphertext()
    {
        // Arrange
        var rewrapResult = new Secret<EncryptionResponse>
        {
            Data = new EncryptionResponse { CipherText = "vault:v2:newcipher" }
        };

        _mockTransit
            .Setup(t => t.RewrapAsync(
                It.IsAny<string>(),
                It.IsAny<RewrapRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(rewrapResult);

        var engine = CreateEngine();

        // Act
        var result = await engine.RewrapAsync("my-key", "vault:v1:oldcipher", cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("vault:v2:newcipher");
    }
}
