using FluentAssertions;
using VaultaX.Abstractions;
using Xunit;

namespace VaultaX.Tests.Engines;

/// <summary>
/// Tests for Transit engine models.
/// </summary>
public class TransitEngineModelsTests
{
    [Fact]
    public void TransitSignRequest_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var request = new TransitSignRequest
        {
            KeyName = "test-key",
            Data = new byte[] { 1, 2, 3 }
        };

        // Assert
        request.KeyName.Should().Be("test-key");
        request.Data.Should().NotBeNull();
        request.HashAlgorithm.Should().Be(TransitHashAlgorithm.Sha256);
        request.SignatureAlgorithm.Should().Be(TransitSignatureAlgorithm.Pss);
        request.KeyVersion.Should().BeNull();
        request.Prehashed.Should().BeFalse();
        request.MarshalingAlgorithm.Should().BeNull();
    }

    [Fact]
    public void TransitSignRequest_CanSetAllProperties()
    {
        // Arrange & Act
        var request = new TransitSignRequest
        {
            KeyName = "my-signing-key",
            Data = new byte[] { 1, 2, 3, 4, 5 },
            HashAlgorithm = TransitHashAlgorithm.Sha512,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pss,
            KeyVersion = 2,
            Prehashed = true,
            MarshalingAlgorithm = TransitMarshalingAlgorithm.Jws
        };

        // Assert
        request.KeyName.Should().Be("my-signing-key");
        request.Data.Should().BeEquivalentTo(new byte[] { 1, 2, 3, 4, 5 });
        request.HashAlgorithm.Should().Be(TransitHashAlgorithm.Sha512);
        request.SignatureAlgorithm.Should().Be(TransitSignatureAlgorithm.Pss);
        request.KeyVersion.Should().Be(2);
        request.Prehashed.Should().BeTrue();
        request.MarshalingAlgorithm.Should().Be(TransitMarshalingAlgorithm.Jws);
    }

    [Fact]
    public void TransitSignResponse_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var response = new TransitSignResponse
        {
            Signature = "vault:v1:test",
            KeyVersion = 1
        };

        // Assert
        response.Signature.Should().NotBeNull();
        response.KeyVersion.Should().Be(1);
    }

    [Fact]
    public void TransitSignResponse_CanSetAllProperties()
    {
        // Arrange & Act
        var response = new TransitSignResponse
        {
            Signature = "vault:v1:signature-data-here",
            KeyVersion = 3
        };

        // Assert
        response.Signature.Should().Be("vault:v1:signature-data-here");
        response.KeyVersion.Should().Be(3);
    }

    [Fact]
    public void TransitVerifyRequest_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var request = new TransitVerifyRequest
        {
            KeyName = "test-key",
            Data = new byte[] { 1, 2, 3 },
            Signature = "vault:v1:test"
        };

        // Assert
        request.KeyName.Should().Be("test-key");
        request.Data.Should().NotBeNull();
        request.Signature.Should().NotBeNull();
        request.HashAlgorithm.Should().Be(TransitHashAlgorithm.Sha256);
        request.SignatureAlgorithm.Should().Be(TransitSignatureAlgorithm.Pss);
        request.Prehashed.Should().BeFalse();
        request.MarshalingAlgorithm.Should().BeNull();
    }

    [Fact]
    public void TransitVerifyRequest_CanSetAllProperties()
    {
        // Arrange & Act
        var request = new TransitVerifyRequest
        {
            KeyName = "my-signing-key",
            Data = new byte[] { 1, 2, 3, 4, 5 },
            Signature = "vault:v1:signature-data",
            HashAlgorithm = TransitHashAlgorithm.Sha384,
            SignatureAlgorithm = TransitSignatureAlgorithm.Pkcs1v15,
            Prehashed = true,
            MarshalingAlgorithm = TransitMarshalingAlgorithm.Asn1
        };

        // Assert
        request.KeyName.Should().Be("my-signing-key");
        request.Data.Should().BeEquivalentTo(new byte[] { 1, 2, 3, 4, 5 });
        request.Signature.Should().Be("vault:v1:signature-data");
        request.HashAlgorithm.Should().Be(TransitHashAlgorithm.Sha384);
        request.SignatureAlgorithm.Should().Be(TransitSignatureAlgorithm.Pkcs1v15);
        request.Prehashed.Should().BeTrue();
        request.MarshalingAlgorithm.Should().Be(TransitMarshalingAlgorithm.Asn1);
    }

    [Fact]
    public void TransitKeyInfo_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var keyInfo = new TransitKeyInfo
        {
            Name = "test-key",
            Type = "aes256-gcm96",
            LatestVersion = 1,
            MinDecryptionVersion = 1,
            MinEncryptionVersion = 1,
            SupportsDrivation = false,
            Exportable = false,
            DeletionAllowed = false
        };

        // Assert
        keyInfo.Name.Should().Be("test-key");
        keyInfo.Type.Should().NotBeNull();
        keyInfo.DeletionAllowed.Should().BeFalse();
        keyInfo.SupportsDrivation.Should().BeFalse();
        keyInfo.Exportable.Should().BeFalse();
        keyInfo.LatestVersion.Should().Be(1);
        keyInfo.MinDecryptionVersion.Should().Be(1);
        keyInfo.MinEncryptionVersion.Should().Be(1);
    }

    [Fact]
    public void TransitKeyInfo_CanSetAllProperties()
    {
        // Arrange & Act
        var keyInfo = new TransitKeyInfo
        {
            Name = "my-transit-key",
            Type = "rsa-4096",
            DeletionAllowed = true,
            SupportsDrivation = false,
            Exportable = false,
            LatestVersion = 5,
            MinDecryptionVersion = 3,
            MinEncryptionVersion = 4
        };

        // Assert
        keyInfo.Name.Should().Be("my-transit-key");
        keyInfo.Type.Should().Be("rsa-4096");
        keyInfo.DeletionAllowed.Should().BeTrue();
        keyInfo.LatestVersion.Should().Be(5);
        keyInfo.MinDecryptionVersion.Should().Be(3);
        keyInfo.MinEncryptionVersion.Should().Be(4);
        keyInfo.SupportsDrivation.Should().BeFalse();
        keyInfo.Exportable.Should().BeFalse();
    }
}
