using System;
using System.Collections.Generic;
using FluentAssertions;
using VaultaX.Configuration;
using Xunit;

namespace VaultaX.Tests.Configuration;

/// <summary>
/// Tests for VaultaX configuration options.
/// </summary>
public class VaultaXOptionsTests
{
    [Fact]
    public void VaultaXOptions_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var options = new VaultaXOptions();

        // Assert
        options.Enabled.Should().BeFalse();
        options.Address.Should().BeEmpty();
        options.MountPoint.Should().Be("secret");
        options.KvVersion.Should().Be(2);
        options.BasePath.Should().BeEmpty();
        options.Authentication.Should().NotBeNull();
        options.Mappings.Should().NotBeNull().And.BeEmpty();
        options.Reload.Should().NotBeNull();
        options.TokenRenewal.Should().NotBeNull();
    }

    [Fact]
    public void AuthenticationOptions_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var options = new AuthenticationOptions();

        // Assert
        options.Method.Should().Be("AppRole");
        options.TokenEnvVar.Should().Be("VAULT_TOKEN");
        options.RoleId.Should().BeNull();
        options.SecretIdEnvVar.Should().Be("VAULT_SECRET_ID");
        options.MountPath.Should().BeEmpty();
    }

    [Fact]
    public void ReloadOptions_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var options = new ReloadOptions();

        // Assert
        options.Enabled.Should().BeFalse();
        options.IntervalSeconds.Should().Be(300);
    }

    [Fact]
    public void TokenRenewalOptions_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var options = new TokenRenewalOptions();

        // Assert
        options.Enabled.Should().BeTrue();
        options.CheckIntervalSeconds.Should().Be(300);
        options.ThresholdPercent.Should().Be(80);
        options.MaxConsecutiveFailures.Should().Be(3);
    }

    [Fact]
    public void SecretMappingOptions_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var options = new SecretMappingOptions();

        // Assert
        options.SecretPath.Should().BeEmpty();
        options.Bindings.Should().NotBeNull().And.BeEmpty();
    }

    [Fact]
    public void SecretMappingOptions_CanAddBindings()
    {
        // Arrange
        var options = new SecretMappingOptions
        {
            SecretPath = "database",
            Bindings = new Dictionary<string, string>
            {
                { "connectionString", "ConnectionStrings:DefaultConnection" },
                { "password", "DatabaseSettings:Password" }
            }
        };

        // Assert
        options.SecretPath.Should().Be("database");
        options.Bindings.Should().HaveCount(2);
        options.Bindings["connectionString"].Should().Be("ConnectionStrings:DefaultConnection");
        options.Bindings["password"].Should().Be("DatabaseSettings:Password");
    }

    [Fact]
    public void AuthenticationOptions_GetToken_ReturnsEnvValue()
    {
        // Arrange
        const string envVarName = "TEST_VAULTAX_TOKEN";
        const string expectedToken = "test-token-value";
        Environment.SetEnvironmentVariable(envVarName, expectedToken);

        var options = new AuthenticationOptions
        {
            TokenEnvVar = envVarName
        };

        try
        {
            // Act
            var token = options.GetToken();

            // Assert
            token.Should().Be(expectedToken);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVarName, null);
        }
    }

    [Fact]
    public void AuthenticationOptions_GetSecretId_ReturnsEnvValue()
    {
        // Arrange
        const string envVarName = "TEST_VAULTAX_SECRET_ID";
        const string expectedSecretId = "test-secret-id";
        Environment.SetEnvironmentVariable(envVarName, expectedSecretId);

        var options = new AuthenticationOptions
        {
            SecretIdEnvVar = envVarName
        };

        try
        {
            // Act
            var secretId = options.GetSecretId();

            // Assert
            secretId.Should().Be(expectedSecretId);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVarName, null);
        }
    }

    [Fact]
    public void VaultaXOptions_CanConfigureFullExample()
    {
        // Arrange & Act
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            MountPoint = "kv",
            KvVersion = 2,
            BasePath = "production",
            Authentication = new AuthenticationOptions
            {
                Method = "AppRole",
                RoleId = "my-role-id",
                SecretIdEnvVar = "VAULT_SECRET_ID"
            },
            Mappings =
            [
                new SecretMappingOptions
                {
                    SecretPath = "database",
                    Bindings = new Dictionary<string, string>
                    {
                        { "connectionString", "ConnectionStrings:Default" }
                    }
                }
            ],
            Reload = new ReloadOptions
            {
                Enabled = true,
                IntervalSeconds = 60
            },
            TokenRenewal = new TokenRenewalOptions
            {
                Enabled = true,
                CheckIntervalSeconds = 30
            }
        };

        // Assert
        options.Enabled.Should().BeTrue();
        options.Address.Should().Be("https://vault.example.com:8200");
        options.BasePath.Should().Be("production");
        options.Authentication.Method.Should().Be("AppRole");
        options.Mappings.Should().HaveCount(1);
        options.Reload.Enabled.Should().BeTrue();
        options.TokenRenewal.Enabled.Should().BeTrue();
    }
}
