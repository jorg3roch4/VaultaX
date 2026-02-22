using System;
using System.IO;
using FluentAssertions;
using VaultaX.Authentication;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods.AppRole;
using VaultSharp.V1.AuthMethods.Custom;
using VaultSharp.V1.AuthMethods.GitHub;
using VaultSharp.V1.AuthMethods.JWT;
using VaultSharp.V1.AuthMethods.Kubernetes;
using VaultSharp.V1.AuthMethods.LDAP;
using VaultSharp.V1.AuthMethods.RADIUS;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods.UserPass;
using Xunit;

namespace VaultaX.Tests.Authentication;

[Collection("Sequential")]
public class AuthMethodTests
{
    // ==================== TokenAuthMethod ====================

    [Fact]
    public void TokenAuthMethod_MethodName_ReturnsToken()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Token", Token = "static:test-token" };
        var method = new TokenAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("Token");
    }

    [Fact]
    public void TokenAuthMethod_GetAuthMethodInfo_ReturnsTokenAuthMethodInfo()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Token", Token = "static:my-token" };
        var method = new TokenAuthMethod(options);

        // Act
        var info = method.GetAuthMethodInfo();

        // Assert
        info.Should().BeOfType<TokenAuthMethodInfo>();
    }

    [Fact]
    public async System.Threading.Tasks.Task TokenAuthMethod_AuthenticateAsync_ReturnsPlaceholderResult()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Token", Token = "static:test" };
        var method = new TokenAuthMethod(options);

        // Act
        var result = await method.AuthenticateAsync(TestContext.Current.CancellationToken);

        // Assert
        result.Token.Should().Be(string.Empty);
        result.Renewable.Should().BeFalse();
    }

    // ==================== AppRoleAuthMethod ====================

    [Fact]
    public void AppRoleAuthMethod_MethodName_ReturnsAppRole()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "AppRole", RoleId = "role", SecretId = "static:secret" };
        var method = new AppRoleAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("AppRole");
    }

    [Fact]
    public void AppRoleAuthMethod_GetAuthMethodInfo_ReturnsAppRoleInfo()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "AppRole",
            RoleId = "my-role-id",
            SecretId = "static:my-secret-id"
        };
        var method = new AppRoleAuthMethod(options);

        // Act
        var info = method.GetAuthMethodInfo();

        // Assert
        info.Should().BeOfType<AppRoleAuthMethodInfo>();
    }

    [Fact]
    public void AppRoleAuthMethod_GetAuthMethodInfo_ThrowsWhenNoRoleId()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "AppRole",
            RoleId = null,
            SecretId = "static:secret"
        };
        var method = new AppRoleAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*RoleId*");
    }

    // ==================== KubernetesAuthMethod ====================

    [Fact]
    public void KubernetesAuthMethod_MethodName_ReturnsKubernetes()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Kubernetes", Role = "k8s-role" };
        var method = new KubernetesAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("Kubernetes");
    }

    [Fact]
    public void KubernetesAuthMethod_GetAuthMethodInfo_ThrowsWhenNoRole()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Kubernetes", Role = null };
        var method = new KubernetesAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Role*");
    }

    [Fact]
    public void KubernetesAuthMethod_GetAuthMethodInfo_ThrowsWhenTokenFileMissing()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "Kubernetes",
            Role = "k8s-role",
            ServiceAccountTokenPath = "/nonexistent/path/token"
        };
        var method = new KubernetesAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*token file not found*");
    }

    [Fact]
    public void KubernetesAuthMethod_GetAuthMethodInfo_ReadsTokenFromFile()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        File.WriteAllText(tempFile, "test-k8s-jwt-token");
        try
        {
            var options = new AuthenticationOptions
            {
                Method = "Kubernetes",
                Role = "k8s-role",
                ServiceAccountTokenPath = tempFile
            };
            var method = new KubernetesAuthMethod(options);

            // Act
            var info = method.GetAuthMethodInfo();

            // Assert
            info.Should().BeOfType<KubernetesAuthMethodInfo>();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    // ==================== LdapAuthMethod ====================

    [Fact]
    public void LdapAuthMethod_MethodName_ReturnsLDAP()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "LDAP", Username = "user", Password = "static:pass" };
        var method = new LdapAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("LDAP");
    }

    [Fact]
    public void LdapAuthMethod_GetAuthMethodInfo_ReturnsLDAPInfo()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "LDAP",
            Username = "ldapuser",
            Password = "static:ldappass"
        };
        var method = new LdapAuthMethod(options);

        // Act
        var info = method.GetAuthMethodInfo();

        // Assert
        info.Should().BeOfType<LDAPAuthMethodInfo>();
    }

    [Fact]
    public void LdapAuthMethod_GetAuthMethodInfo_ThrowsWhenNoUsername()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "LDAP", Username = null, Password = "static:pass" };
        var method = new LdapAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Username*");
    }

    // ==================== JwtOidcAuthMethod ====================

    [Fact]
    public void JwtOidcAuthMethod_MethodName_ReturnsJWT()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "JWT", Role = "jwt-role", Token = "static:jwt" };
        var method = new JwtOidcAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("JWT");
    }

    [Fact]
    public void JwtOidcAuthMethod_GetAuthMethodInfo_ReturnsJWTInfo()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "JWT",
            Role = "jwt-role",
            Token = "static:my-jwt-token"
        };
        var method = new JwtOidcAuthMethod(options);

        // Act
        var info = method.GetAuthMethodInfo();

        // Assert
        info.Should().BeOfType<JWTAuthMethodInfo>();
    }

    [Fact]
    public void JwtOidcAuthMethod_GetAuthMethodInfo_ThrowsWhenNoRole()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "JWT", Role = null, Token = "static:jwt" };
        var method = new JwtOidcAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Role*");
    }

    // ==================== UserPassAuthMethod ====================

    [Fact]
    public void UserPassAuthMethod_MethodName_ReturnsUserPass()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "UserPass", Username = "user", Password = "static:pass" };
        var method = new UserPassAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("UserPass");
    }

    [Fact]
    public void UserPassAuthMethod_GetAuthMethodInfo_ReturnsUserPassInfo()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "UserPass",
            Username = "testuser",
            Password = "static:testpass"
        };
        var method = new UserPassAuthMethod(options);

        // Act
        var info = method.GetAuthMethodInfo();

        // Assert
        info.Should().BeOfType<UserPassAuthMethodInfo>();
    }

    [Fact]
    public void UserPassAuthMethod_GetAuthMethodInfo_ThrowsWhenNoUsername()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "UserPass", Username = null, Password = "static:pass" };
        var method = new UserPassAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Username*");
    }

    // ==================== GitHubAuthMethod ====================

    [Fact]
    public void GitHubAuthMethod_MethodName_ReturnsGitHub()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "GitHub", Token = "static:ghp_test" };
        var method = new GitHubAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("GitHub");
    }

    [Fact]
    public void GitHubAuthMethod_GetAuthMethodInfo_ReturnsGitHubInfo()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "GitHub", Token = "static:ghp_testtoken123" };
        var method = new GitHubAuthMethod(options);

        // Act
        var info = method.GetAuthMethodInfo();

        // Assert
        info.Should().BeOfType<GitHubAuthMethodInfo>();
    }

    // ==================== RadiusAuthMethod ====================

    [Fact]
    public void RadiusAuthMethod_MethodName_ReturnsRADIUS()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "RADIUS", Username = "user", Password = "static:pass" };
        var method = new RadiusAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("RADIUS");
    }

    [Fact]
    public void RadiusAuthMethod_GetAuthMethodInfo_ReturnsRADIUSInfo()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "RADIUS",
            Username = "radiususer",
            Password = "static:radiuspass"
        };
        var method = new RadiusAuthMethod(options);

        // Act
        var info = method.GetAuthMethodInfo();

        // Assert
        info.Should().BeOfType<RADIUSAuthMethodInfo>();
    }

    [Fact]
    public void RadiusAuthMethod_GetAuthMethodInfo_ThrowsWhenNoUsername()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "RADIUS", Username = null, Password = "static:pass" };
        var method = new RadiusAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Username*");
    }

    // ==================== CustomAuthMethod ====================

    [Fact]
    public void CustomAuthMethod_MethodName_ReturnsCustom()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Custom", CustomPath = "auth/custom", CustomValue = "static:val" };
        var method = new CustomAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("Custom");
    }

    [Fact]
    public void CustomAuthMethod_GetAuthMethodInfo_ReturnsCustomInfo()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "Custom",
            CustomPath = "auth/custom/login",
            CustomValue = "static:custom-token"
        };
        var method = new CustomAuthMethod(options);

        // Act
        var info = method.GetAuthMethodInfo();

        // Assert
        info.Should().BeOfType<CustomAuthMethodInfo>();
    }

    [Fact]
    public void CustomAuthMethod_GetAuthMethodInfo_ThrowsWhenNoCustomPath()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Custom", CustomPath = null, CustomValue = "static:val" };
        var method = new CustomAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*CustomPath*");
    }

    // ==================== AwsAuthMethod ====================

    [Fact]
    public void AwsAuthMethod_MethodName_ReturnsAWS()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "AWS", Role = "aws-role" };
        var method = new AwsAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("AWS");
    }

    [Fact]
    public void AwsAuthMethod_GetAuthMethodInfo_ThrowsWhenNoRole()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "AWS", Role = null };
        var method = new AwsAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Role*");
    }

    [Fact]
    public void AwsAuthMethod_GetAuthMethodInfo_ThrowsForUnknownAuthType()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "AWS", Role = "role", AuthType = "unknown" };
        var method = new AwsAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*unknown*");
    }

    // ==================== AzureAuthMethod ====================

    [Fact]
    public void AzureAuthMethod_MethodName_ReturnsAzure()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Azure", Role = "azure-role" };
        var method = new AzureAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("Azure");
    }

    [Fact]
    public void AzureAuthMethod_GetAuthMethodInfo_ThrowsWhenNoRole()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Azure", Role = null };
        var method = new AzureAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*Role*");
    }

    // ==================== CertificateAuthMethod ====================

    [Fact]
    public void CertificateAuthMethod_MethodName_ReturnsCertificate()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Certificate", CertificatePath = "/path/to/cert" };
        var method = new CertificateAuthMethod(options);

        // Act & Assert
        method.MethodName.Should().Be("Certificate");
    }

    [Fact]
    public void CertificateAuthMethod_GetAuthMethodInfo_ThrowsWhenNoCertificatePath()
    {
        // Arrange
        var options = new AuthenticationOptions { Method = "Certificate", CertificatePath = null };
        var method = new CertificateAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*CertificatePath*");
    }

    [Fact]
    public void CertificateAuthMethod_GetAuthMethodInfo_ThrowsWhenCertificateFileNotFound()
    {
        // Arrange
        var options = new AuthenticationOptions
        {
            Method = "Certificate",
            CertificatePath = "/nonexistent/cert.pfx"
        };
        var method = new CertificateAuthMethod(options);

        // Act & Assert
        var action = () => method.GetAuthMethodInfo();
        action.Should().Throw<VaultaXConfigurationException>()
            .WithMessage("*not found*");
    }
}
