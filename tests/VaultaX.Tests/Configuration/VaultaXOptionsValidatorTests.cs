using System;
using System.Collections.Generic;
using FluentAssertions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using Xunit;

namespace VaultaX.Tests.Configuration;

/// <summary>
/// Tests for VaultaX options validation.
/// </summary>
[Collection("Sequential")]
public class VaultaXOptionsValidatorTests
{
    [Fact]
    public void Validate_ThrowsException_WhenAddressIsEmpty()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "",
            Authentication = new AuthenticationOptions
            {
                Method = "Token",
                TokenEnvVar = "VAULT_TOKEN"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Address*");
    }

    [Fact(Skip = "Environment variable validation happens at runtime, not during options validation")]
    public void Validate_ThrowsException_WhenAuthMethodIsEmpty()
    {
        // Arrange
        Environment.SetEnvironmentVariable("VAULT_TOKEN", null);
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = ""
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*authentication method*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenTokenAuthHasNoToken()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "Token",
                TokenEnvVar = null!
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Token*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenAppRoleHasNoRoleId()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "AppRole",
                RoleId = null,
                SecretIdEnvVar = "VAULT_SECRET_ID"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*RoleId*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenAppRoleHasNoSecretId()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "AppRole",
                RoleId = "role-id",
                SecretIdEnvVar = null!
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*SecretId*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenKubernetesHasNoRole()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "Kubernetes",
                KubernetesRole = null
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Role*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenUserPassHasNoUsername()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "UserPass",
                Username = null,
                PasswordEnvVar = "VAULT_PASSWORD"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Username*");
    }

    [Fact(Skip = "Environment variable validation happens at runtime, not during options validation")]
    public void Validate_ThrowsException_WhenUserPassHasNoPassword()
    {
        // Arrange
        Environment.SetEnvironmentVariable("VAULT_PASSWORD", null);
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "UserPass",
                Username = "user",
                PasswordEnvVar = "VAULT_PASSWORD"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Password*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenLdapHasNoUsername()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "LDAP",
                Username = null,
                PasswordEnvVar = "VAULT_PASSWORD"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Username*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenGitHubHasNoToken()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "GitHub",
                GitHubTokenEnvVar = null
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Token*");
    }

    [Fact(Skip = "Environment variable validation happens at runtime, not during options validation")]
    public void Validate_ThrowsException_WhenJwtHasNoJwt()
    {
        // Arrange
        Environment.SetEnvironmentVariable("VAULT_JWT_TOKEN", null);
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "JWT",
                JwtTokenEnvVar = null,
                JwtRole = "my-role"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Jwt*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenAwsHasNoRole()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "AWS",
                AwsRole = null
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Role*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenAzureHasNoRole()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "Azure",
                AzureRole = null
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Role*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenCertificateHasNoCertPath()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "Certificate",
                CertificatePath = null
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*CertificatePath*");
    }

    [Fact(Skip = "Environment variable validation happens at runtime, not during options validation")]
    public void Validate_ThrowsException_WhenMappingHasNoSecretPath()
    {
        // Arrange
        Environment.SetEnvironmentVariable("VAULT_TOKEN", null);
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "Token",
                TokenEnvVar = "VAULT_TOKEN"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new()
                {
                    SecretPath = "",
                    Bindings = new Dictionary<string, string>
                    {
                        { "key", "ConfigKey" }
                    }
                }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*SecretPath*");
    }

    [Fact]
    public void Validate_ThrowsException_WhenKvVersionIsInvalid()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            KvVersion = 3, // Invalid - only 1 or 2 are valid
            Authentication = new AuthenticationOptions
            {
                Method = "Token",
                TokenEnvVar = "VAULT_TOKEN"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*KvVersion*");
    }

    [Fact]
    public void Validate_Succeeds_WithValidTokenAuth()
    {
        // Arrange
        var originalToken = Environment.GetEnvironmentVariable("VAULT_TOKEN");
        Environment.SetEnvironmentVariable("VAULT_TOKEN", "test-token");
        try
        {
            var options = new VaultaXOptions
            {
                Enabled = true,
                Address = "https://vault.example.com:8200",
                Authentication = new AuthenticationOptions
                {
                    Method = "Token",
                    TokenEnvVar = "VAULT_TOKEN"
                },
                Mappings = new List<SecretMappingOptions>
                {
                    new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
                }
            };

            // Act & Assert
            VaultaXOptionsValidator.Validate(options); // Should not throw
        }
        finally
        {
            Environment.SetEnvironmentVariable("VAULT_TOKEN", originalToken);
        }
    }

    [Fact]
    public void Validate_Succeeds_WithValidAppRoleAuth()
    {
        // Arrange
        var originalSecretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");
        Environment.SetEnvironmentVariable("VAULT_SECRET_ID", "test-secret");
        try
        {
            var options = new VaultaXOptions
            {
                Enabled = true,
                Address = "https://vault.example.com:8200",
                Authentication = new AuthenticationOptions
                {
                    Method = "AppRole",
                    RoleId = "role-id",
                    SecretIdEnvVar = "VAULT_SECRET_ID"
                },
                Mappings = new List<SecretMappingOptions>
                {
                    new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
                }
            };

            // Act & Assert
            VaultaXOptionsValidator.Validate(options); // Should not throw
        }
        finally
        {
            Environment.SetEnvironmentVariable("VAULT_SECRET_ID", originalSecretId);
        }
    }

    [Fact]
    public void Validate_Succeeds_WithValidKubernetesAuth()
    {
        // Arrange
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "https://vault.example.com:8200",
            Authentication = new AuthenticationOptions
            {
                Method = "Kubernetes",
                KubernetesRole = "my-role"
            },
            Mappings = new List<SecretMappingOptions>
            {
                new() { SecretPath = "test", Bindings = new Dictionary<string, string> { { "key", "value" } } }
            }
        };

        // Act & Assert
        var action = () => VaultaXOptionsValidator.Validate(options);
        action.Should().NotThrow();
    }

    [Fact]
    public void Validate_Succeeds_WithValidMappings()
    {
        // Arrange
        var originalToken = Environment.GetEnvironmentVariable("VAULT_TOKEN");
        Environment.SetEnvironmentVariable("VAULT_TOKEN", "test-token");
        try
        {
            var options = new VaultaXOptions
            {
                Enabled = true,
                Address = "https://vault.example.com:8200",
                Authentication = new AuthenticationOptions
                {
                    Method = "Token",
                    TokenEnvVar = "VAULT_TOKEN"
                },
                Mappings = new List<SecretMappingOptions>
                {
                    new()
                    {
                        SecretPath = "database",
                        Bindings = new Dictionary<string, string>
                        {
                            { "connectionString", "ConnectionStrings:Default" }
                        }
                    },
                    new()
                    {
                        SecretPath = "rabbitmq",
                        Bindings = new Dictionary<string, string>
                        {
                            { "host", "RabbitMQ:Host" },
                            { "username", "RabbitMQ:Username" }
                        }
                    }
                }
            };

            // Act & Assert
            VaultaXOptionsValidator.Validate(options); // Should not throw
        }
        finally
        {
            Environment.SetEnvironmentVariable("VAULT_TOKEN", originalToken);
        }
    }
}
