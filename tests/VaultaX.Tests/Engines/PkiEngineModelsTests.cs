using System;
using System.Collections.Generic;
using FluentAssertions;
using VaultaX.Abstractions;
using Xunit;

namespace VaultaX.Tests.Engines;

/// <summary>
/// Tests for PKI engine models.
/// </summary>
public class PkiEngineModelsTests
{
    [Fact]
    public void PkiCertificateRequest_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var request = new PkiCertificateRequest
        {
            RoleName = "test-role",
            CommonName = "test.example.com"
        };

        // Assert
        request.RoleName.Should().Be("test-role");
        request.CommonName.Should().Be("test.example.com");
        request.AltNames.Should().BeNull();
        request.IpSans.Should().BeNull();
        request.UriSans.Should().BeNull();
        request.Ttl.Should().BeNull();
        request.Format.Should().Be("pem");
        request.PrivateKeyFormat.Should().Be("der");
        request.ExcludeCnFromSans.Should().BeFalse();
    }

    [Fact]
    public void PkiCertificateRequest_CanSetAllProperties()
    {
        // Arrange & Act
        var request = new PkiCertificateRequest
        {
            RoleName = "web-server",
            CommonName = "api.example.com",
            AltNames = new List<string> { "www.example.com", "cdn.example.com" },
            IpSans = new List<string> { "10.0.0.1", "192.168.1.100" },
            UriSans = new List<string> { "spiffe://cluster.local/ns/default/sa/api" },
            Ttl = "720h",
            Format = "pem",
            PrivateKeyFormat = "der",
            ExcludeCnFromSans = true
        };

        // Assert
        request.RoleName.Should().Be("web-server");
        request.CommonName.Should().Be("api.example.com");
        request.AltNames.Should().BeEquivalentTo(new[] { "www.example.com", "cdn.example.com" });
        request.IpSans.Should().BeEquivalentTo(new[] { "10.0.0.1", "192.168.1.100" });
        request.UriSans.Should().BeEquivalentTo(new[] { "spiffe://cluster.local/ns/default/sa/api" });
        request.Ttl.Should().Be("720h");
        request.Format.Should().Be("pem");
        request.PrivateKeyFormat.Should().Be("der");
        request.ExcludeCnFromSans.Should().BeTrue();
    }

    [Fact]
    public void PkiCertificateResponse_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var response = new PkiCertificateResponse
        {
            Certificate = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
            SerialNumber = "00:11:22:33",
            Expiration = DateTimeOffset.UtcNow.AddDays(30)
        };

        // Assert
        response.Certificate.Should().NotBeNull();
        response.IssuingCa.Should().BeNull();
        response.CaChain.Should().BeNull();
        response.PrivateKey.Should().BeNull();
        response.PrivateKeyType.Should().BeNull();
        response.SerialNumber.Should().NotBeNull();
        response.Expiration.Should().NotBe(default);
    }

    [Fact]
    public void PkiCertificateResponse_CanSetAllProperties()
    {
        // Arrange
        var expiration = DateTimeOffset.UtcNow.AddDays(30);

        // Act
        var response = new PkiCertificateResponse
        {
            Certificate = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            IssuingCa = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            CaChain = new List<string>
            {
                "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----"
            },
            PrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
            PrivateKeyType = "rsa",
            SerialNumber = "5a:33:ab:f7:12:34:56:78",
            Expiration = expiration
        };

        // Assert
        response.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
        response.IssuingCa.Should().StartWith("-----BEGIN CERTIFICATE-----");
        response.CaChain.Should().HaveCount(2);
        response.PrivateKey.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
        response.PrivateKeyType.Should().Be("rsa");
        response.SerialNumber.Should().Be("5a:33:ab:f7:12:34:56:78");
        response.Expiration.Should().Be(expiration);
    }

    [Fact]
    public void PkiCertificateRequest_AltNames_CanBeEmpty()
    {
        // Arrange & Act
        var request = new PkiCertificateRequest
        {
            RoleName = "internal",
            CommonName = "service.internal",
            AltNames = new List<string>()
        };

        // Assert
        request.AltNames.Should().NotBeNull();
        request.AltNames.Should().BeEmpty();
    }

    [Fact]
    public void PkiCertificateRequest_TtlFormats_AreValid()
    {
        // Test various TTL formats that Vault accepts
        var validTtls = new[] { "720h", "30d", "1h30m", "3600s", "8760h" };

        foreach (var ttl in validTtls)
        {
            var request = new PkiCertificateRequest
            {
                RoleName = "test",
                CommonName = "test.example.com",
                Ttl = ttl
            };

            request.Ttl.Should().Be(ttl);
        }
    }
}
