using System;
using System.Collections.Generic;
using FluentAssertions;
using VaultaX.Abstractions;
using VaultaX.BackgroundServices;
using Xunit;

namespace VaultaX.Tests.Abstractions;

public class ModelTests
{
    // ==================== AuthResult ====================

    [Fact]
    public void AuthResult_Properties_AreSetCorrectly()
    {
        // Arrange & Act
        var result = new AuthResult
        {
            Token = "s.testtoken",
            LeaseDuration = TimeSpan.FromHours(1),
            Renewable = true,
            Accessor = "accessor-123",
            Policies = new[] { "default", "admin" },
            Metadata = new Dictionary<string, string> { { "role", "admin" } }
        };

        // Assert
        result.Token.Should().Be("s.testtoken");
        result.LeaseDuration.Should().Be(TimeSpan.FromHours(1));
        result.Renewable.Should().BeTrue();
        result.Accessor.Should().Be("accessor-123");
        result.Policies.Should().BeEquivalentTo(new[] { "default", "admin" });
        result.Metadata.Should().ContainKey("role");
    }

    [Fact]
    public void AuthResult_OptionalProperties_DefaultToNull()
    {
        // Arrange & Act
        var result = new AuthResult
        {
            Token = "token",
            LeaseDuration = TimeSpan.Zero,
            Renewable = false
        };

        // Assert
        result.Accessor.Should().BeNull();
        result.Policies.Should().BeNull();
        result.Metadata.Should().BeNull();
    }

    // ==================== SecretMetadata ====================

    [Fact]
    public void SecretMetadata_Properties_AreSetCorrectly()
    {
        // Arrange
        var created = DateTimeOffset.UtcNow.AddHours(-1);
        var updated = DateTimeOffset.UtcNow;

        // Act
        var metadata = new SecretMetadata
        {
            CurrentVersion = 5,
            OldestVersion = 1,
            CreatedTime = created,
            UpdatedTime = updated,
            MaxVersions = 10,
            CasRequired = true
        };

        // Assert
        metadata.CurrentVersion.Should().Be(5);
        metadata.OldestVersion.Should().Be(1);
        metadata.CreatedTime.Should().Be(created);
        metadata.UpdatedTime.Should().Be(updated);
        metadata.MaxVersions.Should().Be(10);
        metadata.CasRequired.Should().BeTrue();
    }

    // ==================== TokenInfo ====================

    [Fact]
    public void TokenInfo_ExpiresAt_IsCalculatedCorrectly()
    {
        // Arrange
        var createdAt = DateTimeOffset.UtcNow;
        var leaseDuration = TimeSpan.FromHours(1);

        // Act
        var tokenInfo = new TokenInfo
        {
            Token = "token",
            CreatedAt = createdAt,
            LeaseDuration = leaseDuration,
            Renewable = true
        };

        // Assert
        tokenInfo.ExpiresAt.Should().Be(createdAt + leaseDuration);
    }

    [Fact]
    public void TokenInfo_RemainingTime_DecreasesOverTime()
    {
        // Arrange & Act
        var tokenInfo = new TokenInfo
        {
            Token = "token",
            CreatedAt = DateTimeOffset.UtcNow,
            LeaseDuration = TimeSpan.FromHours(1),
            Renewable = true
        };

        // Assert
        tokenInfo.RemainingTime.Should().BeCloseTo(TimeSpan.FromHours(1), TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void TokenInfo_ElapsedPercent_IsZeroWhenJustCreated()
    {
        // Arrange & Act
        var tokenInfo = new TokenInfo
        {
            Token = "token",
            CreatedAt = DateTimeOffset.UtcNow,
            LeaseDuration = TimeSpan.FromHours(1),
            Renewable = true
        };

        // Assert
        tokenInfo.ElapsedPercent.Should().BeInRange(0, 1);
    }

    [Fact]
    public void TokenInfo_ElapsedPercent_Is100WhenLeaseDurationIsZero()
    {
        // Arrange & Act
        var tokenInfo = new TokenInfo
        {
            Token = "token",
            CreatedAt = DateTimeOffset.UtcNow,
            LeaseDuration = TimeSpan.Zero,
            Renewable = false
        };

        // Assert
        tokenInfo.ElapsedPercent.Should().Be(100);
    }

    [Fact]
    public void TokenInfo_IsExpired_FalseWhenNotExpired()
    {
        // Arrange & Act
        var tokenInfo = new TokenInfo
        {
            Token = "token",
            CreatedAt = DateTimeOffset.UtcNow,
            LeaseDuration = TimeSpan.FromHours(1),
            Renewable = true
        };

        // Assert
        tokenInfo.IsExpired.Should().BeFalse();
    }

    [Fact]
    public void TokenInfo_IsExpired_TrueWhenExpired()
    {
        // Arrange & Act
        var tokenInfo = new TokenInfo
        {
            Token = "token",
            CreatedAt = DateTimeOffset.UtcNow.AddHours(-2),
            LeaseDuration = TimeSpan.FromHours(1),
            Renewable = true
        };

        // Assert
        tokenInfo.IsExpired.Should().BeTrue();
    }

    // ==================== TokenRenewedEventArgs ====================

    [Fact]
    public void TokenRenewedEventArgs_Properties_AreSetCorrectly()
    {
        // Arrange
        var renewedAt = DateTimeOffset.UtcNow;

        // Act
        var args = new TokenRenewedEventArgs
        {
            NewLeaseDuration = TimeSpan.FromHours(1),
            RenewedAt = renewedAt
        };

        // Assert
        args.NewLeaseDuration.Should().Be(TimeSpan.FromHours(1));
        args.RenewedAt.Should().Be(renewedAt);
    }

    // ==================== TokenReauthenticatedEventArgs ====================

    [Fact]
    public void TokenReauthenticatedEventArgs_Properties_AreSetCorrectly()
    {
        // Arrange
        var authAt = DateTimeOffset.UtcNow;

        // Act
        var args = new TokenReauthenticatedEventArgs
        {
            LeaseDuration = TimeSpan.FromHours(2),
            AuthenticatedAt = authAt,
            Reason = "Max failures reached"
        };

        // Assert
        args.LeaseDuration.Should().Be(TimeSpan.FromHours(2));
        args.AuthenticatedAt.Should().Be(authAt);
        args.Reason.Should().Be("Max failures reached");
    }

    // ==================== TokenRenewalFailedEventArgs ====================

    [Fact]
    public void TokenRenewalFailedEventArgs_Properties_AreSetCorrectly()
    {
        // Arrange
        var exception = new Exception("renewal failed");

        // Act
        var args = new TokenRenewalFailedEventArgs
        {
            Exception = exception,
            ConsecutiveFailures = 3,
            WillReauthenticate = true
        };

        // Assert
        args.Exception.Should().BeSameAs(exception);
        args.ConsecutiveFailures.Should().Be(3);
        args.WillReauthenticate.Should().BeTrue();
    }

    // ==================== SecretsChangedEventArgs ====================

    [Fact]
    public void SecretsChangedEventArgs_Constructor_SetsChangedSecrets()
    {
        // Arrange
        var secrets = new List<string> { "database", "api-keys" };

        // Act
        var args = new SecretsChangedEventArgs(secrets);

        // Assert
        args.ChangedSecrets.Should().BeEquivalentTo(new[] { "database", "api-keys" });
    }

    // ==================== TransitSignResponse.GetSignatureBytes ====================

    [Fact]
    public void TransitSignResponse_GetSignatureBytes_WithVaultPrefix_ExtractsBase64()
    {
        // Arrange
        var base64Data = Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5 });
        var response = new TransitSignResponse
        {
            Signature = $"vault:v1:{base64Data}",
            KeyVersion = 1
        };

        // Act
        var bytes = response.GetSignatureBytes();

        // Assert
        bytes.Should().BeEquivalentTo(new byte[] { 1, 2, 3, 4, 5 });
    }

    [Fact]
    public void TransitSignResponse_GetSignatureBytes_WithoutPrefix_DecodesDirectly()
    {
        // Arrange
        var base64Data = Convert.ToBase64String(new byte[] { 10, 20, 30 });
        var response = new TransitSignResponse
        {
            Signature = base64Data,
            KeyVersion = 1
        };

        // Act
        var bytes = response.GetSignatureBytes();

        // Assert
        bytes.Should().BeEquivalentTo(new byte[] { 10, 20, 30 });
    }
}
