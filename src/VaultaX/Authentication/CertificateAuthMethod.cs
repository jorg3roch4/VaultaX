using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Cert;

namespace VaultaX.Authentication;

/// <summary>
/// TLS Certificate authentication method using client certificates.
/// </summary>
public sealed class CertificateAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "Certificate";

    /// <summary>
    /// Creates a new Certificate authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public CertificateAuthMethod(AuthenticationOptions options) : base(options)
    {
    }

    /// <inheritdoc />
    public override Task<AuthResult> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new AuthResult
        {
            Token = string.Empty,
            LeaseDuration = TimeSpan.Zero,
            Renewable = true
        });
    }

    /// <inheritdoc />
    public override IAuthMethodInfo GetAuthMethodInfo()
    {
        if (string.IsNullOrWhiteSpace(Options.CertificatePath))
        {
            throw new VaultaXConfigurationException(
                "CertificatePath is required for Certificate authentication.",
                "VaultaX:Authentication:CertificatePath");
        }

        if (!File.Exists(Options.CertificatePath))
        {
            throw new VaultaXConfigurationException(
                $"Certificate file not found at: {Options.CertificatePath}",
                "VaultaX:Authentication:CertificatePath");
        }

        var password = GetOptionalEnvVar(Options.CertificatePassword);
        var mountPath = GetMountPath("cert");

        X509Certificate2 certificate;
        try
        {
            certificate = string.IsNullOrEmpty(password)
                ? X509CertificateLoader.LoadCertificateFromFile(Options.CertificatePath)
                : X509CertificateLoader.LoadPkcs12FromFile(Options.CertificatePath, password);
        }
        catch (Exception ex)
        {
            throw new VaultaXConfigurationException(
                $"Failed to load certificate from {Options.CertificatePath}: {ex.Message}",
                ex);
        }

        return new CertAuthMethodInfo(mountPath, certificate, Options.Role);
    }
}
