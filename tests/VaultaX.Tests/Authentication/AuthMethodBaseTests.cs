using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using VaultaX.Abstractions;
using VaultaX.Authentication;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using Xunit;

namespace VaultaX.Tests.Authentication;

[Collection("Sequential")]
public class AuthMethodBaseTests
{
    private sealed class TestAuthMethod : AuthMethodBase
    {
        public override string MethodName => "Test";

        public TestAuthMethod(AuthenticationOptions options) : base(options) { }

        public override Task<AuthResult> AuthenticateAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new AuthResult { Token = "t", LeaseDuration = TimeSpan.Zero, Renewable = false });

        public override IAuthMethodInfo GetAuthMethodInfo() => new TokenAuthMethodInfo("test");

        // Expose protected methods for testing
        public string TestGetMountPath(string defaultPath) => GetMountPath(defaultPath);
        public static string TestGetRequiredEnvVar(string? envVarName, string description) => GetRequiredEnvVar(envVarName, description);
        public static string? TestGetOptionalEnvVar(string? envVarName) => GetOptionalEnvVar(envVarName);
    }

    [Fact]
    public void GetMountPath_WhenMountPathEmpty_ReturnsDefault()
    {
        // Arrange
        var options = new AuthenticationOptions { MountPath = "" };
        var method = new TestAuthMethod(options);

        // Act
        var result = method.TestGetMountPath("approle");

        // Assert
        result.Should().Be("approle");
    }

    [Fact]
    public void GetMountPath_WhenMountPathConfigured_ReturnsConfigured()
    {
        // Arrange
        var options = new AuthenticationOptions { MountPath = "custom-approle" };
        var method = new TestAuthMethod(options);

        // Act
        var result = method.TestGetMountPath("approle");

        // Assert
        result.Should().Be("custom-approle");
    }

    [Fact]
    public void GetRequiredEnvVar_WithStaticPrefix_ReturnsValue()
    {
        // Arrange & Act
        var result = TestAuthMethod.TestGetRequiredEnvVar("static:my-secret-value", "test");

        // Assert
        result.Should().Be("my-secret-value");
    }

    [Fact]
    public void GetRequiredEnvVar_WithEnvPrefix_ReadsEnvironmentVariable()
    {
        // Arrange
        var envKey = $"VAULTAX_TEST_{Guid.NewGuid():N}";
        Environment.SetEnvironmentVariable(envKey, "env-value");
        try
        {
            // Act
            var result = TestAuthMethod.TestGetRequiredEnvVar($"env:{envKey}", "test");

            // Assert
            result.Should().Be("env-value");
        }
        finally
        {
            Environment.SetEnvironmentVariable(envKey, null);
        }
    }

    [Fact]
    public void GetRequiredEnvVar_WithBareEnvVarName_ReadsEnvironmentVariable()
    {
        // Arrange
        var envKey = $"VAULTAX_TEST_{Guid.NewGuid():N}";
        Environment.SetEnvironmentVariable(envKey, "bare-value");
        try
        {
            // Act
            var result = TestAuthMethod.TestGetRequiredEnvVar(envKey, "test");

            // Assert
            result.Should().Be("bare-value");
        }
        finally
        {
            Environment.SetEnvironmentVariable(envKey, null);
        }
    }

    [Fact]
    public void GetRequiredEnvVar_WhenNotSet_ThrowsVaultaXConfigurationException()
    {
        // Arrange
        var envKey = $"VAULTAX_MISSING_{Guid.NewGuid():N}";

        // Act & Assert
        var action = () => TestAuthMethod.TestGetRequiredEnvVar(envKey, "missing var");
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage($"*{envKey}*");
    }

    [Fact]
    public void GetRequiredEnvVar_WhenNull_ThrowsVaultaXConfigurationException()
    {
        // Act & Assert
        var action = () => TestAuthMethod.TestGetRequiredEnvVar(null, "null var");
        action.Should().Throw<VaultaXConfigurationException>();
    }

    [Fact]
    public void GetOptionalEnvVar_WithStaticPrefix_ReturnsValue()
    {
        // Arrange & Act
        var result = TestAuthMethod.TestGetOptionalEnvVar("static:optional-value");

        // Assert
        result.Should().Be("optional-value");
    }

    [Fact]
    public void GetOptionalEnvVar_WhenNull_ReturnsNull()
    {
        // Arrange & Act
        var result = TestAuthMethod.TestGetOptionalEnvVar(null);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetOptionalEnvVar_WhenNotSet_ReturnsNull()
    {
        // Arrange
        var envKey = $"VAULTAX_OPTIONAL_{Guid.NewGuid():N}";

        // Act
        var result = TestAuthMethod.TestGetOptionalEnvVar(envKey);

        // Assert
        result.Should().BeNull();
    }
}
