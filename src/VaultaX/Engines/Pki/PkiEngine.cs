using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using VaultaX.Abstractions;
using VaultaX.Exceptions;
using VaultSharp.V1.SecretsEngines.PKI;

namespace VaultaX.Engines.Pki;

/// <summary>
/// Implementation of the PKI secrets engine for certificate management.
/// </summary>
public sealed class PkiEngine : IPkiEngine
{
    private readonly IVaultClient _vaultClient;
    private readonly string _mountPoint;
    private readonly ILogger<PkiEngine>? _logger;

    /// <summary>
    /// Creates a new PKI engine instance.
    /// </summary>
    /// <param name="vaultClient">The Vault client.</param>
    /// <param name="mountPoint">The mount point for the PKI engine (default: "pki").</param>
    /// <param name="logger">Optional logger.</param>
    public PkiEngine(
        IVaultClient vaultClient,
        string mountPoint = "pki",
        ILogger<PkiEngine>? logger = null)
    {
        _vaultClient = vaultClient ?? throw new ArgumentNullException(nameof(vaultClient));
        _mountPoint = mountPoint ?? "pki";
        _logger = logger;
    }

    /// <inheritdoc />
    public string EngineType => "pki";

    /// <inheritdoc />
    public string MountPoint => _mountPoint;

    /// <inheritdoc />
    public async Task<PkiCertificateResponse> IssueCertificateAsync(
        PkiCertificateRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.RoleName);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.CommonName);

        _logger?.LogDebug(
            "Issuing certificate for {CommonName} using role {RoleName}",
            request.CommonName,
            request.RoleName);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();

            var issueOptions = new CertificateCredentialsRequestOptions
            {
                CommonName = request.CommonName,
                CertificateFormat = MapFormat(request.Format),
                PrivateKeyFormat = MapPrivateKeyFormat(request.PrivateKeyFormat),
                ExcludeCommonNameFromSubjectAlternativeNames = request.ExcludeCnFromSans
            };

            if (request.AltNames != null && request.AltNames.Count > 0)
            {
                issueOptions.SubjectAlternativeNames = string.Join(",", request.AltNames);
            }

            if (request.IpSans != null && request.IpSans.Count > 0)
            {
                issueOptions.IPSubjectAlternativeNames = string.Join(",", request.IpSans);
            }

            if (request.UriSans != null && request.UriSans.Count > 0)
            {
                issueOptions.URISubjectAlternativeNames = string.Join(",", request.UriSans);
            }

            if (!string.IsNullOrWhiteSpace(request.Ttl))
            {
                issueOptions.TimeToLive = request.Ttl;
            }

            var result = await client.V1.Secrets.PKI.GetCredentialsAsync(
                pkiRoleName: request.RoleName,
                certificateCredentialRequestOptions: issueOptions,
                pkiBackendMountPoint: _mountPoint).ConfigureAwait(false);

            _logger?.LogInformation(
                "Certificate issued successfully for {CommonName}, serial: {SerialNumber}",
                request.CommonName,
                result.Data.SerialNumber);

            return new PkiCertificateResponse
            {
                Certificate = result.Data.CertificateContent,
                PrivateKey = result.Data.PrivateKeyContent,
                PrivateKeyType = result.Data.PrivateKeyType.ToString(),
                SerialNumber = result.Data.SerialNumber,
                IssuingCa = result.Data.IssuingCACertificateContent,
                CaChain = result.Data.CAChainContent?.ToList(),
                Expiration = DateTimeOffset.FromUnixTimeSeconds(result.Data.Expiration)
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to issue certificate for {CommonName}", request.CommonName);
            throw new VaultPkiException($"Failed to issue certificate: {ex.Message}", "issue", ex);
        }
    }

    /// <inheritdoc />
    public async Task<PkiCertificateResponse> SignCsrAsync(
        string roleName,
        string csr,
        string commonName,
        string? ttl = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(roleName);
        ArgumentException.ThrowIfNullOrWhiteSpace(csr);
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

        _logger?.LogDebug("Signing CSR for {CommonName} using role {RoleName}", commonName, roleName);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();

            var signOptions = new SignCertificatesRequestOptions
            {
                CommonName = commonName
            };

            if (!string.IsNullOrWhiteSpace(ttl))
            {
                signOptions.TimeToLive = ttl;
            }

            var result = await client.V1.Secrets.PKI.SignCertificateAsync(
                roleName,
                signOptions,
                _mountPoint).ConfigureAwait(false);

            _logger?.LogInformation(
                "CSR signed successfully for {CommonName}, serial: {SerialNumber}",
                commonName,
                result.Data.SerialNumber);

            return new PkiCertificateResponse
            {
                Certificate = result.Data.CertificateContent,
                SerialNumber = result.Data.SerialNumber,
                IssuingCa = result.Data.IssuingCACertificateContent,
                CaChain = result.Data.CAChainContent?.ToList(),
                Expiration = DateTimeOffset.MinValue // Expiration not available in SignedCertificateData
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to sign CSR for {CommonName}", commonName);
            throw new VaultPkiException($"Failed to sign CSR: {ex.Message}", "sign", ex);
        }
    }

    /// <inheritdoc />
    public async Task RevokeCertificateAsync(
        string serialNumber,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serialNumber);

        _logger?.LogDebug("Revoking certificate with serial {SerialNumber}", serialNumber);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();

            await client.V1.Secrets.PKI.RevokeCertificateAsync(
                serialNumber: serialNumber,
                pkiBackendMountPoint: _mountPoint).ConfigureAwait(false);

            _logger?.LogInformation("Certificate revoked successfully: {SerialNumber}", serialNumber);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to revoke certificate {SerialNumber}", serialNumber);
            throw new VaultPkiException($"Failed to revoke certificate: {ex.Message}", "revoke", ex);
        }
    }

    /// <inheritdoc />
    public async Task<string> GetCaCertificateAsync(
        string format = "pem",
        CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("Getting CA certificate in {Format} format", format);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();

            var result = await client.V1.Secrets.PKI.ReadCACertificateAsync(
                certificateFormat: MapFormat(format),
                pkiBackendMountPoint: _mountPoint).ConfigureAwait(false);

            return result.CertificateContent;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get CA certificate");
            throw new VaultPkiException($"Failed to get CA certificate: {ex.Message}", "read-ca", ex);
        }
    }

    /// <inheritdoc />
    public async Task<string> GetCertificateChainAsync(CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("Getting certificate chain");

        try
        {
            var client = _vaultClient.GetUnderlyingClient();

            var result = await client.V1.Secrets.PKI.ReadDefaultIssuerCertificateChainAsync(
                certificateFormat: CertificateFormat.pem,
                pkiBackendMountPoint: _mountPoint).ConfigureAwait(false);

            return result.Data.CertificateContent;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get certificate chain");
            throw new VaultPkiException($"Failed to get certificate chain: {ex.Message}", "read-chain", ex);
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> ListCertificatesAsync(CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("Listing certificates");

        try
        {
            var client = _vaultClient.GetUnderlyingClient();

            var result = await client.V1.Secrets.PKI.ListCertificatesAsync(
                pkiBackendMountPoint: _mountPoint).ConfigureAwait(false);

            return result.Data.Keys?.ToList() ?? [];
        }
        catch (VaultSharp.Core.VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return [];
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to list certificates");
            throw new VaultPkiException($"Failed to list certificates: {ex.Message}", "list", ex);
        }
    }

    private static CertificateFormat MapFormat(string format)
    {
        return format?.ToLowerInvariant() switch
        {
            "pem" => CertificateFormat.pem,
            "der" => CertificateFormat.der,
            "pem_bundle" => CertificateFormat.pem_bundle,
            _ => CertificateFormat.pem
        };
    }

    private static PrivateKeyFormat MapPrivateKeyFormat(string format)
    {
        return format?.ToLowerInvariant() switch
        {
            "der" => PrivateKeyFormat.der,
            "pkcs8" => PrivateKeyFormat.pkcs8,
            _ => PrivateKeyFormat.der
        };
    }
}
