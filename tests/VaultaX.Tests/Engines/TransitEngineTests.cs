using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using VaultaX.Abstractions;
using VaultaX.Engines.Transit;
using VaultaX.Engines.Transit.Models;
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

    // ==================== Certificate Chain Support (v1.1.0) ====================

    private const string SamplePem = "-----BEGIN CERTIFICATE-----\nMIIDAzCCAeugAwIBAgI=\n-----END CERTIFICATE-----\n";

    private static X509Certificate2 CreateSelfSignedCert(byte[] serialBytes)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=vaultax-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = notBefore.AddHours(1);
        return req.Create(
            new X500DistinguishedName("CN=vaultax-test"),
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            notBefore,
            notAfter,
            serialBytes);
    }

    private static string ExportCertPem(X509Certificate2 cert) => cert.ExportCertificatePem();

    [Fact]
    public async Task SetCertificateChainAsync_Success_SendsExpectedRequest()
    {
        // Arrange
        HttpMethod? capturedMethod = null;
        string? capturedPath = null;
        object? capturedBody = null;

        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitRawVoidResponse>(
                It.IsAny<HttpMethod>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()))
            .Callback<HttpMethod, string, object?, CancellationToken>((m, p, b, _) =>
            {
                capturedMethod = m;
                capturedPath = p;
                capturedBody = b;
            })
            .ReturnsAsync((TransitRawVoidResponse?)null);

        var engine = CreateEngine();

        // Act
        await engine.SetCertificateChainAsync("payments-signing", SamplePem, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        capturedMethod.Should().Be(HttpMethod.Post);
        capturedPath.Should().Be("transit/keys/payments-signing/set-certificate");
        capturedBody.Should().NotBeNull();
        capturedBody!.GetType().GetProperty("certificate_chain")!.GetValue(capturedBody)
            .Should().Be(SamplePem);
    }

    [Fact]
    public async Task SetCertificateChainAsync_WithKeyVersion_IncludesVersionInBody()
    {
        // Arrange
        object? capturedBody = null;

        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitRawVoidResponse>(
                It.IsAny<HttpMethod>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()))
            .Callback<HttpMethod, string, object?, CancellationToken>((_, _, b, _) => capturedBody = b)
            .ReturnsAsync((TransitRawVoidResponse?)null);

        var engine = CreateEngine();

        // Act
        await engine.SetCertificateChainAsync("payments-signing", SamplePem, keyVersion: 3,
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        capturedBody.Should().NotBeNull();
        var type = capturedBody!.GetType();
        type.GetProperty("certificate_chain")!.GetValue(capturedBody).Should().Be(SamplePem);
        type.GetProperty("version")!.GetValue(capturedBody).Should().Be(3);
    }

    [Theory]
    [InlineData(null, "pem")]
    [InlineData("", "pem")]
    [InlineData("  ", "pem")]
    [InlineData("key", null)]
    [InlineData("key", "")]
    public async Task SetCertificateChainAsync_InvalidArgs_Throws(string? keyName, string? pem)
    {
        var engine = CreateEngine();
        var act = async () => await engine.SetCertificateChainAsync(keyName!, pem!,
            cancellationToken: TestContext.Current.CancellationToken);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task GetCertificateChainAsync_Success_ReturnsLatestPem()
    {
        // Arrange
        var response = new TransitExportCertResponse
        {
            Data = new TransitExportCertData
            {
                Keys = new Dictionary<string, string>
                {
                    ["1"] = "old-pem",
                    ["2"] = SamplePem
                }
            }
        };

        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitExportCertResponse>(
                HttpMethod.Get,
                "transit/export/certificate-chain/payments-signing",
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCertificateChainAsync("payments-signing",
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be(SamplePem);
    }

    [Fact]
    public async Task GetCertificateChainAsync_SpecificVersion_CallsVersionedPath()
    {
        // Arrange
        var response = new TransitExportCertResponse
        {
            Data = new TransitExportCertData
            {
                Keys = new Dictionary<string, string> { ["2"] = SamplePem }
            }
        };

        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitExportCertResponse>(
                HttpMethod.Get,
                "transit/export/certificate-chain/payments-signing/2",
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCertificateChainAsync("payments-signing", version: 2,
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be(SamplePem);
    }

    [Fact]
    public async Task GetCertificateChainAsync_NotFound_ReturnsNull()
    {
        // Arrange
        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitExportCertResponse>(
                It.IsAny<HttpMethod>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((TransitExportCertResponse?)null);

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCertificateChainAsync("payments-signing",
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetCertificateChainAsync_EmptyKeysMap_ReturnsNull()
    {
        // Arrange
        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitExportCertResponse>(
                It.IsAny<HttpMethod>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TransitExportCertResponse { Data = new TransitExportCertData { Keys = new Dictionary<string, string>() } });

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCertificateChainAsync("payments-signing",
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetCertificateSerialAsync_Decimal_ReturnsBigIntegerString()
    {
        // Arrange — serial 0x0102030405 (big-endian) = 4328719365 decimal
        var serial = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        using var cert = CreateSelfSignedCert(serial);
        var pem = ExportCertPem(cert);

        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitExportCertResponse>(
                It.IsAny<HttpMethod>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TransitExportCertResponse
            {
                Data = new TransitExportCertData { Keys = new Dictionary<string, string> { ["1"] = pem } }
            });

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCertificateSerialAsync("payments-signing",
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("4328719365");
    }

    [Fact]
    public async Task GetCertificateSerialAsync_Hex_ReturnsUppercaseHex()
    {
        // Arrange — first byte < 0x80 to avoid ASN.1 DER sign-padding ("00" prefix).
        var serial = new byte[] { 0x12, 0xAB, 0xCD, 0xEF };
        using var cert = CreateSelfSignedCert(serial);
        var pem = ExportCertPem(cert);

        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitExportCertResponse>(
                It.IsAny<HttpMethod>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TransitExportCertResponse
            {
                Data = new TransitExportCertData { Keys = new Dictionary<string, string> { ["1"] = pem } }
            });

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCertificateSerialAsync("payments-signing", format: SerialFormat.Hex,
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("12ABCDEF");
    }

    [Fact]
    public async Task GetCertificateSerialAsync_NoCertificate_ReturnsNull()
    {
        // Arrange
        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitExportCertResponse>(
                It.IsAny<HttpMethod>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((TransitExportCertResponse?)null);

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCertificateSerialAsync("payments-signing",
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetCertificateSerialAsync_MalformedPem_Throws()
    {
        // Arrange
        _mockClient
            .Setup(c => c.SendRawRequestAsync<TransitExportCertResponse>(
                It.IsAny<HttpMethod>(),
                It.IsAny<string>(),
                It.IsAny<object?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TransitExportCertResponse
            {
                Data = new TransitExportCertData { Keys = new Dictionary<string, string> { ["1"] = "not-a-real-pem" } }
            });

        var engine = CreateEngine();

        // Act
        var act = async () => await engine.GetCertificateSerialAsync("payments-signing",
            cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        var ex = await act.Should().ThrowAsync<VaultTransitException>();
        ex.Which.Operation.Should().Be("get-certificate-serial");
    }
}
