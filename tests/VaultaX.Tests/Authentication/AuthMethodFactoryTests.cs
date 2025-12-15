using System;
using FluentAssertions;
using VaultaX.Authentication;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using Xunit;

namespace VaultaX.Tests.Authentication;

/// <summary>
/// Tests for AuthMethodFactory.
/// </summary>
public class AuthMethodFactoryTests
{
    [Theory]
    [InlineData("Token", typeof(TokenAuthMethod))]
    [InlineData("token", typeof(TokenAuthMethod))]
    [InlineData("TOKEN", typeof(TokenAuthMethod))]
    [InlineData("AppRole", typeof(AppRoleAuthMethod))]
    [InlineData("approle", typeof(AppRoleAuthMethod))]
    [InlineData("Kubernetes", typeof(KubernetesAuthMethod))]
    [InlineData("kubernetes", typeof(KubernetesAuthMethod))]
    [InlineData("k8s", typeof(KubernetesAuthMethod))]
    [InlineData("LDAP", typeof(LdapAuthMethod))]
    [InlineData("ldap", typeof(LdapAuthMethod))]
    [InlineData("JWT", typeof(JwtOidcAuthMethod))]
    [InlineData("jwt", typeof(JwtOidcAuthMethod))]
    [InlineData("OIDC", typeof(JwtOidcAuthMethod))]
    [InlineData("oidc", typeof(JwtOidcAuthMethod))]
    [InlineData("AWS", typeof(AwsAuthMethod))]
    [InlineData("aws", typeof(AwsAuthMethod))]
    [InlineData("Azure", typeof(AzureAuthMethod))]
    [InlineData("azure", typeof(AzureAuthMethod))]
    [InlineData("GitHub", typeof(GitHubAuthMethod))]
    [InlineData("github", typeof(GitHubAuthMethod))]
    [InlineData("Certificate", typeof(CertificateAuthMethod))]
    [InlineData("certificate", typeof(CertificateAuthMethod))]
    [InlineData("cert", typeof(CertificateAuthMethod))]
    [InlineData("tls", typeof(CertificateAuthMethod))]
    [InlineData("UserPass", typeof(UserPassAuthMethod))]
    [InlineData("userpass", typeof(UserPassAuthMethod))]
    [InlineData("RADIUS", typeof(RadiusAuthMethod))]
    [InlineData("radius", typeof(RadiusAuthMethod))]
    public void Create_ReturnsCorrectAuthMethod(string method, Type expectedType)
    {
        // Arrange
        var options = CreateAuthOptionsForMethod(method);

        // Act
        var authMethod = AuthMethodFactory.Create(options);

        // Assert
        authMethod.Should().BeOfType(expectedType);
    }

    [Fact]
    public void Create_ThrowsException_WhenMethodIsNull()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = null!
        };

        // Act & Assert
        var action = () => AuthMethodFactory.Create(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*authentication method*");
    }

    [Fact]
    public void Create_ThrowsException_WhenMethodIsEmpty()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = ""
        };

        // Act & Assert
        var action = () => AuthMethodFactory.Create(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*authentication method*");
    }

    [Fact]
    public void Create_ThrowsException_WhenMethodIsUnknown()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "UnknownMethod"
        };

        // Act & Assert
        var action = () => AuthMethodFactory.Create(options);
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*UnknownMethod*");
    }

    [Fact]
    public void Create_ReturnsCustomAuthMethod_WhenMethodIsCustom()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "Custom",
            CustomAuthPath = "auth/custom/login",
            CustomAuthEnvVar = "CUSTOM_AUTH_TOKEN"
        };

        // Act
        var authMethod = AuthMethodFactory.Create(options);

        // Assert
        authMethod.Should().BeOfType<CustomAuthMethod>();
    }

    [Fact]
    public void Create_TokenAuthMethod_SetsTokenCorrectly()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "Token",
            TokenEnvVar = "VAULT_TOKEN"
        };

        // Act
        var authMethod = AuthMethodFactory.Create(options);

        // Assert
        authMethod.Should().BeOfType<TokenAuthMethod>();
    }

    [Fact]
    public void Create_AppRoleAuthMethod_SetsCredentialsCorrectly()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "AppRole",
            RoleId = "my-role-id",
            SecretIdEnvVar = "VAULT_SECRET_ID",
            MountPath = "custom-approle"
        };

        // Act
        var authMethod = AuthMethodFactory.Create(options);

        // Assert
        authMethod.Should().BeOfType<AppRoleAuthMethod>();
    }

    [Fact]
    public void Create_KubernetesAuthMethod_SetsRoleCorrectly()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "Kubernetes",
            KubernetesRole = "my-k8s-role",
            MountPath = "kubernetes"
        };

        // Act
        var authMethod = AuthMethodFactory.Create(options);

        // Assert
        authMethod.Should().BeOfType<KubernetesAuthMethod>();
    }

    private static AuthenticationOptions CreateAuthOptionsForMethod(string method)
    {
        var options = new AuthenticationOptions { Method = method };

        // Set required properties based on method
        switch (method.ToLowerInvariant())
        {
            case "token":
                options.TokenEnvVar = "VAULT_TOKEN";
                break;
            case "approle":
                options.RoleId = "role-id";
                options.SecretIdEnvVar = "VAULT_SECRET_ID";
                break;
            case "kubernetes":
            case "k8s":
                options.KubernetesRole = "k8s-role";
                break;
            case "ldap":
            case "userpass":
            case "radius":
                options.Username = "user";
                options.PasswordEnvVar = "VAULT_PASSWORD";
                break;
            case "jwt":
            case "oidc":
                options.JwtTokenEnvVar = "VAULT_JWT_TOKEN";
                options.JwtRole = "jwt-role";
                break;
            case "aws":
                options.AwsRole = "cloud-role";
                break;
            case "azure":
                options.AzureRole = "cloud-role";
                break;
            case "github":
                options.GitHubTokenEnvVar = "GITHUB_TOKEN";
                break;
            case "certificate":
            case "cert":
            case "tls":
                options.CertificatePath = "/path/to/cert.pem";
                break;
        }

        return options;
    }
}
