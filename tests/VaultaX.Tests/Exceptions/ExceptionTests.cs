using System;
using FluentAssertions;
using VaultaX.Exceptions;
using Xunit;

namespace VaultaX.Tests.Exceptions;

public class ExceptionTests
{
    // ==================== VaultaXException ====================

    [Fact]
    public void VaultaXException_DefaultConstructor_CreatesInstance()
    {
        // Arrange & Act
        var ex = new VaultaXException();

        // Assert
        ex.Message.Should().NotBeNullOrEmpty();
        ex.InnerException.Should().BeNull();
    }

    [Fact]
    public void VaultaXException_MessageConstructor_SetsMessage()
    {
        // Arrange & Act
        var ex = new VaultaXException("test message");

        // Assert
        ex.Message.Should().Be("test message");
    }

    [Fact]
    public void VaultaXException_MessageAndInnerException_SetsBoth()
    {
        // Arrange
        var inner = new InvalidOperationException("inner");

        // Act
        var ex = new VaultaXException("outer", inner);

        // Assert
        ex.Message.Should().Be("outer");
        ex.InnerException.Should().BeSameAs(inner);
    }

    // ==================== VaultaXConfigurationException ====================

    [Fact]
    public void VaultaXConfigurationException_MessageConstructor_SetsMessage()
    {
        // Arrange & Act
        var ex = new VaultaXConfigurationException("config error");

        // Assert
        ex.Message.Should().Be("config error");
        ex.ConfigurationKey.Should().BeNull();
    }

    [Fact]
    public void VaultaXConfigurationException_WithConfigKey_SetsBoth()
    {
        // Arrange & Act
        var ex = new VaultaXConfigurationException("config error", "VaultaX:Address");

        // Assert
        ex.Message.Should().Be("config error");
        ex.ConfigurationKey.Should().Be("VaultaX:Address");
    }

    [Fact]
    public void VaultaXConfigurationException_WithInnerException_SetsBoth()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultaXConfigurationException("outer", inner);

        // Assert
        ex.Message.Should().Be("outer");
        ex.InnerException.Should().BeSameAs(inner);
    }

    // ==================== VaultAuthenticationException ====================

    [Fact]
    public void VaultAuthenticationException_MessageConstructor_SetsMessage()
    {
        // Arrange & Act
        var ex = new VaultAuthenticationException("auth failed");

        // Assert
        ex.Message.Should().Be("auth failed");
        ex.AuthMethod.Should().BeNull();
    }

    [Fact]
    public void VaultAuthenticationException_WithAuthMethod_SetsBoth()
    {
        // Arrange & Act
        var ex = new VaultAuthenticationException("auth failed", "AppRole");

        // Assert
        ex.Message.Should().Be("auth failed");
        ex.AuthMethod.Should().Be("AppRole");
    }

    [Fact]
    public void VaultAuthenticationException_WithInnerException_SetsBoth()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultAuthenticationException("auth failed", inner);

        // Assert
        ex.Message.Should().Be("auth failed");
        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void VaultAuthenticationException_WithAuthMethodAndInner_SetsAll()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultAuthenticationException("auth failed", "Token", inner);

        // Assert
        ex.Message.Should().Be("auth failed");
        ex.AuthMethod.Should().Be("Token");
        ex.InnerException.Should().BeSameAs(inner);
    }

    // ==================== VaultConnectionException ====================

    [Fact]
    public void VaultConnectionException_MessageConstructor_SetsMessage()
    {
        // Arrange & Act
        var ex = new VaultConnectionException("connection failed");

        // Assert
        ex.Message.Should().Be("connection failed");
        ex.VaultAddress.Should().BeNull();
    }

    [Fact]
    public void VaultConnectionException_WithAddress_SetsBoth()
    {
        // Arrange & Act
        var ex = new VaultConnectionException("connection failed", "http://vault:8200");

        // Assert
        ex.Message.Should().Be("connection failed");
        ex.VaultAddress.Should().Be("http://vault:8200");
    }

    [Fact]
    public void VaultConnectionException_WithInnerException_SetsBoth()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultConnectionException("connection failed", inner);

        // Assert
        ex.Message.Should().Be("connection failed");
        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void VaultConnectionException_WithAddressAndInner_SetsAll()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultConnectionException("connection failed", "http://vault:8200", inner);

        // Assert
        ex.Message.Should().Be("connection failed");
        ex.VaultAddress.Should().Be("http://vault:8200");
        ex.InnerException.Should().BeSameAs(inner);
    }

    // ==================== VaultSecretNotFoundException ====================

    [Fact]
    public void VaultSecretNotFoundException_PathOnly_AutoGeneratesMessage()
    {
        // Arrange & Act
        var ex = new VaultSecretNotFoundException("my/secret/path");

        // Assert
        ex.Message.Should().Contain("my/secret/path");
        ex.SecretPath.Should().Be("my/secret/path");
    }

    [Fact]
    public void VaultSecretNotFoundException_MessageAndPath_SetsBoth()
    {
        // Arrange & Act
        var ex = new VaultSecretNotFoundException("custom message", "my/path");

        // Assert
        ex.Message.Should().Be("custom message");
        ex.SecretPath.Should().Be("my/path");
    }

    [Fact]
    public void VaultSecretNotFoundException_PathAndInner_SetsAll()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultSecretNotFoundException("my/path", inner);

        // Assert
        ex.Message.Should().Contain("my/path");
        ex.SecretPath.Should().Be("my/path");
        ex.InnerException.Should().BeSameAs(inner);
    }

    // ==================== VaultTokenRenewalException ====================

    [Fact]
    public void VaultTokenRenewalException_MessageConstructor_SetsMessage()
    {
        // Arrange & Act
        var ex = new VaultTokenRenewalException("renewal failed");

        // Assert
        ex.Message.Should().Be("renewal failed");
        ex.ConsecutiveFailures.Should().Be(0);
    }

    [Fact]
    public void VaultTokenRenewalException_WithFailureCount_SetsBoth()
    {
        // Arrange & Act
        var ex = new VaultTokenRenewalException("renewal failed", 3);

        // Assert
        ex.Message.Should().Be("renewal failed");
        ex.ConsecutiveFailures.Should().Be(3);
    }

    [Fact]
    public void VaultTokenRenewalException_WithInnerException_SetsBoth()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultTokenRenewalException("renewal failed", inner);

        // Assert
        ex.Message.Should().Be("renewal failed");
        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void VaultTokenRenewalException_WithFailureCountAndInner_SetsAll()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultTokenRenewalException("renewal failed", 5, inner);

        // Assert
        ex.Message.Should().Be("renewal failed");
        ex.ConsecutiveFailures.Should().Be(5);
        ex.InnerException.Should().BeSameAs(inner);
    }

    // ==================== VaultTransitException ====================

    [Fact]
    public void VaultTransitException_MessageConstructor_SetsMessage()
    {
        // Arrange & Act
        var ex = new VaultTransitException("transit failed");

        // Assert
        ex.Message.Should().Be("transit failed");
        ex.Operation.Should().BeNull();
        ex.KeyName.Should().BeNull();
    }

    [Fact]
    public void VaultTransitException_WithOperationAndKey_SetsAll()
    {
        // Arrange & Act
        var ex = new VaultTransitException("encrypt failed", "encrypt", "my-key");

        // Assert
        ex.Message.Should().Be("encrypt failed");
        ex.Operation.Should().Be("encrypt");
        ex.KeyName.Should().Be("my-key");
    }

    [Fact]
    public void VaultTransitException_WithOperationOnly_SetsOperationKeyNull()
    {
        // Arrange & Act
        var ex = new VaultTransitException("hash failed", "hash");

        // Assert
        ex.Message.Should().Be("hash failed");
        ex.Operation.Should().Be("hash");
        ex.KeyName.Should().BeNull();
    }

    [Fact]
    public void VaultTransitException_WithInnerException_SetsBoth()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultTransitException("transit failed", inner);

        // Assert
        ex.Message.Should().Be("transit failed");
        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void VaultTransitException_WithOperationKeyAndInner_SetsAll()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultTransitException("encrypt failed", "encrypt", "my-key", inner);

        // Assert
        ex.Message.Should().Be("encrypt failed");
        ex.Operation.Should().Be("encrypt");
        ex.KeyName.Should().Be("my-key");
        ex.InnerException.Should().BeSameAs(inner);
    }

    // ==================== VaultPkiException ====================

    [Fact]
    public void VaultPkiException_MessageConstructor_SetsMessage()
    {
        // Arrange & Act
        var ex = new VaultPkiException("pki failed");

        // Assert
        ex.Message.Should().Be("pki failed");
        ex.Operation.Should().BeNull();
    }

    [Fact]
    public void VaultPkiException_WithOperation_SetsBoth()
    {
        // Arrange & Act
        var ex = new VaultPkiException("issue failed", "issue");

        // Assert
        ex.Message.Should().Be("issue failed");
        ex.Operation.Should().Be("issue");
    }

    [Fact]
    public void VaultPkiException_WithInnerException_SetsBoth()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultPkiException("pki failed", inner);

        // Assert
        ex.Message.Should().Be("pki failed");
        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void VaultPkiException_WithOperationAndInner_SetsAll()
    {
        // Arrange
        var inner = new Exception("inner");

        // Act
        var ex = new VaultPkiException("revoke failed", "revoke", inner);

        // Assert
        ex.Message.Should().Be("revoke failed");
        ex.Operation.Should().Be("revoke");
        ex.InnerException.Should().BeSameAs(inner);
    }

    // ==================== Inheritance ====================

    [Fact]
    public void AllExceptions_InheritFromVaultaXException()
    {
        // Assert
        typeof(VaultaXConfigurationException).Should().BeDerivedFrom<VaultaXException>();
        typeof(VaultAuthenticationException).Should().BeDerivedFrom<VaultaXException>();
        typeof(VaultConnectionException).Should().BeDerivedFrom<VaultaXException>();
        typeof(VaultSecretNotFoundException).Should().BeDerivedFrom<VaultaXException>();
        typeof(VaultTokenRenewalException).Should().BeDerivedFrom<VaultaXException>();
        typeof(VaultTransitException).Should().BeDerivedFrom<VaultaXException>();
        typeof(VaultPkiException).Should().BeDerivedFrom<VaultaXException>();
    }

    [Fact]
    public void VaultaXException_InheritsFromException()
    {
        // Assert
        typeof(VaultaXException).Should().BeDerivedFrom<Exception>();
    }
}
