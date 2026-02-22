using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using VaultaX.Abstractions;
using VaultaX.Engines.Pki;
using VaultaX.Exceptions;
using VaultaX.Tests.Helpers;
using VaultSharp.V1.Commons;
using VaultSharp.V1.SecretsEngines.PKI;
using Xunit;

namespace VaultaX.Tests.Engines;

public class PkiEngineTests
{
    private readonly Mock<IVaultClient> _mockClient;
    private readonly Mock<VaultSharp.IVaultClient> _mockVaultSharp;
    private readonly Mock<IPKISecretsEngine> _mockPki;

    public PkiEngineTests()
    {
        (_mockClient, _mockVaultSharp) = VaultMockHelper.CreateMockVaultClient();

        _mockPki = new Mock<IPKISecretsEngine>();

        var mockSecrets = new Mock<VaultSharp.V1.SecretsEngines.ISecretsEngine>();
        mockSecrets.Setup(s => s.PKI).Returns(_mockPki.Object);

        var mockV1 = new Mock<VaultSharp.V1.IVaultClientV1>();
        mockV1.Setup(v => v.Secrets).Returns(mockSecrets.Object);
        _mockVaultSharp.Setup(c => c.V1).Returns(mockV1.Object);
    }

    private PkiEngine CreateEngine(string mountPoint = "pki")
        => new(_mockClient.Object, mountPoint);

    [Fact]
    public void Constructor_WithNullVaultClient_Throws()
    {
        // Act & Assert
        var action = () => new PkiEngine(null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void EngineType_ReturnsPki()
    {
        // Arrange
        var engine = CreateEngine();

        // Act & Assert
        engine.EngineType.Should().Be("pki");
    }

    [Fact]
    public void MountPoint_ReturnsConfiguredValue()
    {
        // Arrange
        var engine = CreateEngine("custom-pki");

        // Act & Assert
        engine.MountPoint.Should().Be("custom-pki");
    }

    [Fact]
    public async Task IssueCertificateAsync_ReturnsCertificateResponse()
    {
        // Arrange
        var certData = new CertificateCredentials
        {
            CertificateContent = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            PrivateKeyContent = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
            PrivateKeyType = CertificateKeyType.rsa,
            SerialNumber = "00:11:22:33",
            IssuingCACertificateContent = "-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----",
            CAChainContent = new[] { "chain-cert" },
            Expiration = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds()
        };

        var secret = new Secret<CertificateCredentials> { Data = certData };

        _mockPki
            .Setup(p => p.GetCredentialsAsync(
                It.IsAny<string>(),
                It.IsAny<CertificateCredentialsRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();
        var request = new PkiCertificateRequest
        {
            RoleName = "web-role",
            CommonName = "test.example.com"
        };

        // Act
        var result = await engine.IssueCertificateAsync(request, TestContext.Current.CancellationToken);

        // Assert
        result.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
        result.PrivateKey.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
        result.SerialNumber.Should().Be("00:11:22:33");
        result.IssuingCa.Should().Contain("CA");
    }

    [Fact]
    public async Task IssueCertificateAsync_WithAltNames_PassesOptions()
    {
        // Arrange
        var certData = new CertificateCredentials
        {
            CertificateContent = "cert",
            SerialNumber = "aa:bb",
            PrivateKeyType = CertificateKeyType.rsa,
            Expiration = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds()
        };
        var secret = new Secret<CertificateCredentials> { Data = certData };

        _mockPki
            .Setup(p => p.GetCredentialsAsync(
                It.IsAny<string>(),
                It.Is<CertificateCredentialsRequestOptions>(o =>
                    o.SubjectAlternativeNames == "alt1.com,alt2.com" &&
                    o.IPSubjectAlternativeNames == "10.0.0.1" &&
                    o.URISubjectAlternativeNames == "spiffe://test" &&
                    o.TimeToLive == "720h"),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();
        var request = new PkiCertificateRequest
        {
            RoleName = "web-role",
            CommonName = "test.example.com",
            AltNames = new List<string> { "alt1.com", "alt2.com" },
            IpSans = new List<string> { "10.0.0.1" },
            UriSans = new List<string> { "spiffe://test" },
            Ttl = "720h"
        };

        // Act
        var result = await engine.IssueCertificateAsync(request, TestContext.Current.CancellationToken);

        // Assert
        result.Should().NotBeNull();
    }

    [Fact]
    public async Task IssueCertificateAsync_OnError_ThrowsVaultPkiException()
    {
        // Arrange
        _mockPki
            .Setup(p => p.GetCredentialsAsync(
                It.IsAny<string>(),
                It.IsAny<CertificateCredentialsRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ThrowsAsync(new Exception("issue error"));

        var engine = CreateEngine();
        var request = new PkiCertificateRequest
        {
            RoleName = "web-role",
            CommonName = "test.example.com"
        };

        // Act & Assert
        var action = () => engine.IssueCertificateAsync(request);
        await action.Should().ThrowAsync<VaultPkiException>()
            .WithMessage("*Failed to issue certificate*");
    }

    [Fact]
    public async Task SignCsrAsync_ReturnsSignedCertificate()
    {
        // Arrange
        var signedData = new SignedCertificateData
        {
            CertificateContent = "signed-cert",
            SerialNumber = "cc:dd",
            IssuingCACertificateContent = "issuing-ca"
        };
        var secret = new Secret<SignedCertificateData> { Data = signedData };

        _mockPki
            .Setup(p => p.SignCertificateAsync(
                It.IsAny<string>(),
                It.IsAny<SignCertificatesRequestOptions>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();

        // Act
        var result = await engine.SignCsrAsync("web-role", "-----BEGIN CERTIFICATE REQUEST-----", "test.com", cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Certificate.Should().Be("signed-cert");
        result.SerialNumber.Should().Be("cc:dd");
    }

    [Fact]
    public async Task RevokeCertificateAsync_CallsRevoke()
    {
        // Arrange
        var engine = CreateEngine();

        // Act
        await engine.RevokeCertificateAsync("aa:bb:cc:dd", TestContext.Current.CancellationToken);

        // Assert
        _mockPki.Verify(p => p.RevokeCertificateAsync(
            "aa:bb:cc:dd",
            It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task RevokeCertificateAsync_OnError_ThrowsVaultPkiException()
    {
        // Arrange
        _mockPki
            .Setup(p => p.RevokeCertificateAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new Exception("revoke error"));

        var engine = CreateEngine();

        // Act & Assert
        var action = () => engine.RevokeCertificateAsync("aa:bb");
        await action.Should().ThrowAsync<VaultPkiException>()
            .WithMessage("*Failed to revoke certificate*");
    }

    [Fact]
    public async Task GetCaCertificateAsync_ReturnsCACert()
    {
        // Arrange
        var caCert = new RawCertificateData { CertificateContent = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----" };

        _mockPki
            .Setup(p => p.ReadCACertificateAsync(
                It.IsAny<CertificateFormat>(),
                It.IsAny<string>()))
            .ReturnsAsync(caCert);

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCaCertificateAsync(cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        result.Should().Contain("BEGIN CERTIFICATE");
    }

    [Fact]
    public async Task GetCertificateChainAsync_ReturnsChain()
    {
        // Arrange
        var chainData = new CertificateData { CertificateContent = "chain-content" };
        var secret = new Secret<CertificateData> { Data = chainData };

        _mockPki
            .Setup(p => p.ReadDefaultIssuerCertificateChainAsync(
                It.IsAny<CertificateFormat>(),
                It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();

        // Act
        var result = await engine.GetCertificateChainAsync(TestContext.Current.CancellationToken);

        // Assert
        result.Should().Be("chain-content");
    }

    [Fact]
    public async Task ListCertificatesAsync_ReturnsSerialNumbers()
    {
        // Arrange
        var certKeys = new CertificateKeys { Keys = new List<string> { "aa:bb:cc", "dd:ee:ff" } };
        var secret = new Secret<CertificateKeys> { Data = certKeys };

        _mockPki
            .Setup(p => p.ListCertificatesAsync(It.IsAny<string>()))
            .ReturnsAsync(secret);

        var engine = CreateEngine();

        // Act
        var result = await engine.ListCertificatesAsync(TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeEquivalentTo(new[] { "aa:bb:cc", "dd:ee:ff" });
    }

    [Fact]
    public async Task ListCertificatesAsync_On404_ReturnsEmpty()
    {
        // Arrange
        _mockPki
            .Setup(p => p.ListCertificatesAsync(It.IsAny<string>()))
            .ThrowsAsync(new VaultSharp.Core.VaultApiException(HttpStatusCode.NotFound, "not found"));

        var engine = CreateEngine();

        // Act
        var result = await engine.ListCertificatesAsync(TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeEmpty();
    }
}
