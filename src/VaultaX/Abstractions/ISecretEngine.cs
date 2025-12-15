using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace VaultaX.Abstractions;

/// <summary>
/// Base interface for all secret engines.
/// </summary>
public interface ISecretEngine
{
    /// <summary>
    /// The type of this secret engine (e.g., "kv", "transit", "pki").
    /// </summary>
    string EngineType { get; }

    /// <summary>
    /// The mount point for this engine.
    /// </summary>
    string MountPoint { get; }
}

/// <summary>
/// Interface for the Key-Value secrets engine.
/// </summary>
public interface IKeyValueEngine : ISecretEngine
{
    /// <summary>
    /// Reads a secret from the KV engine.
    /// </summary>
    /// <param name="path">The secret path.</param>
    /// <param name="version">The version to read (null for latest, KV v2 only).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The secret data as key-value pairs.</returns>
    Task<IDictionary<string, object?>> ReadAsync(
        string path,
        int? version = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads a secret and deserializes it to the specified type.
    /// </summary>
    /// <typeparam name="T">The type to deserialize to.</typeparam>
    /// <param name="path">The secret path.</param>
    /// <param name="version">The version to read (null for latest, KV v2 only).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The deserialized secret.</returns>
    Task<T> ReadAsync<T>(
        string path,
        int? version = null,
        CancellationToken cancellationToken = default) where T : class, new();

    /// <summary>
    /// Writes a secret to the KV engine.
    /// </summary>
    /// <param name="path">The secret path.</param>
    /// <param name="data">The data to write.</param>
    /// <param name="checkAndSet">For KV v2, the expected version for CAS (null to disable).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task WriteAsync(
        string path,
        IDictionary<string, object?> data,
        int? checkAndSet = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a secret.
    /// </summary>
    /// <param name="path">The secret path.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task DeleteAsync(
        string path,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists secrets at a path.
    /// </summary>
    /// <param name="path">The path to list.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of secret names at the path.</returns>
    Task<IReadOnlyList<string>> ListAsync(
        string path,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets metadata for a secret (KV v2 only).
    /// </summary>
    /// <param name="path">The secret path.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The secret metadata.</returns>
    Task<SecretMetadata?> GetMetadataAsync(
        string path,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Interface for the Transit secrets engine (encryption as a service).
/// </summary>
public interface ITransitEngine : ISecretEngine
{
    /// <summary>
    /// Encrypts data using a named encryption key.
    /// </summary>
    /// <param name="keyName">The name of the encryption key in Vault.</param>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="context">Optional context for key derivation (for derived keys).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The encrypted ciphertext.</returns>
    Task<string> EncryptAsync(
        string keyName,
        byte[] plaintext,
        byte[]? context = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts data using a named encryption key.
    /// </summary>
    /// <param name="keyName">The name of the encryption key in Vault.</param>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="context">Optional context for key derivation (for derived keys).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decrypted plaintext.</returns>
    Task<byte[]> DecryptAsync(
        string keyName,
        string ciphertext,
        byte[]? context = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs data using a named signing key.
    /// The private key never leaves Vault.
    /// </summary>
    /// <param name="request">The signing request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature.</returns>
    Task<TransitSignResponse> SignAsync(
        TransitSignRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a signature.
    /// </summary>
    /// <param name="request">The verification request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the signature is valid.</returns>
    Task<bool> VerifyAsync(
        TransitVerifyRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <param name="format">Output format (hex or base64).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The hash value.</returns>
    Task<string> HashAsync(
        byte[] data,
        TransitHashAlgorithm algorithm = TransitHashAlgorithm.Sha256,
        TransitOutputFormat format = TransitOutputFormat.Base64,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates an HMAC of the input data.
    /// </summary>
    /// <param name="keyName">The name of the key to use.</param>
    /// <param name="data">The data to HMAC.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The HMAC value.</returns>
    Task<string> HmacAsync(
        string keyName,
        byte[] data,
        TransitHashAlgorithm algorithm = TransitHashAlgorithm.Sha256,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates random bytes.
    /// </summary>
    /// <param name="byteCount">Number of bytes to generate.</param>
    /// <param name="format">Output format (hex or base64).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The random bytes as a string.</returns>
    Task<string> GenerateRandomBytesAsync(
        int byteCount,
        TransitOutputFormat format = TransitOutputFormat.Base64,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets information about a transit key.
    /// </summary>
    /// <param name="keyName">The name of the key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Key information.</returns>
    Task<TransitKeyInfo?> GetKeyInfoAsync(
        string keyName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Re-wraps ciphertext with the latest version of a key.
    /// </summary>
    /// <param name="keyName">The name of the key.</param>
    /// <param name="ciphertext">The ciphertext to rewrap.</param>
    /// <param name="context">Optional context for derived keys.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The rewrapped ciphertext.</returns>
    Task<string> RewrapAsync(
        string keyName,
        string ciphertext,
        byte[]? context = null,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Interface for the PKI secrets engine.
/// </summary>
public interface IPkiEngine : ISecretEngine
{
    /// <summary>
    /// Issues a new certificate.
    /// </summary>
    /// <param name="request">The certificate request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issued certificate.</returns>
    Task<PkiCertificateResponse> IssueCertificateAsync(
        PkiCertificateRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs a CSR with the CA.
    /// </summary>
    /// <param name="roleName">The PKI role to use.</param>
    /// <param name="csr">The CSR in PEM format.</param>
    /// <param name="commonName">The common name for the certificate.</param>
    /// <param name="ttl">The certificate TTL.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed certificate.</returns>
    Task<PkiCertificateResponse> SignCsrAsync(
        string roleName,
        string csr,
        string commonName,
        string? ttl = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a certificate.
    /// </summary>
    /// <param name="serialNumber">The certificate serial number.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeCertificateAsync(
        string serialNumber,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the CA certificate.
    /// </summary>
    /// <param name="format">The output format (pem or der).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The CA certificate.</returns>
    Task<string> GetCaCertificateAsync(
        string format = "pem",
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the certificate chain.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The certificate chain in PEM format.</returns>
    Task<string> GetCertificateChainAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists certificates.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of certificate serial numbers.</returns>
    Task<IReadOnlyList<string>> ListCertificatesAsync(
        CancellationToken cancellationToken = default);
}

// ==================== Transit Engine Models ====================

/// <summary>
/// Request to sign data with the Transit engine.
/// </summary>
public sealed record TransitSignRequest
{
    /// <summary>
    /// The name of the signing key in Vault.
    /// </summary>
    public required string KeyName { get; init; }

    /// <summary>
    /// The data to sign.
    /// </summary>
    public required byte[] Data { get; init; }

    /// <summary>
    /// The hash algorithm to use.
    /// </summary>
    public TransitHashAlgorithm HashAlgorithm { get; init; } = TransitHashAlgorithm.Sha256;

    /// <summary>
    /// The signature algorithm for RSA keys.
    /// </summary>
    public TransitSignatureAlgorithm SignatureAlgorithm { get; init; } = TransitSignatureAlgorithm.Pss;

    /// <summary>
    /// If true, the data is already hashed.
    /// </summary>
    public bool Prehashed { get; init; }

    /// <summary>
    /// Optional context for derived keys.
    /// </summary>
    public byte[]? Context { get; init; }

    /// <summary>
    /// The key version to use (null for latest).
    /// </summary>
    public int? KeyVersion { get; init; }

    /// <summary>
    /// Salt length for PSS signatures (-1 for auto, 0 for hash length).
    /// </summary>
    public int? SaltLength { get; init; }

    /// <summary>
    /// Marshaling algorithm for ECDSA signatures.
    /// </summary>
    public TransitMarshalingAlgorithm? MarshalingAlgorithm { get; init; }
}

/// <summary>
/// Response from signing with the Transit engine.
/// </summary>
public sealed record TransitSignResponse
{
    /// <summary>
    /// The signature in Vault format (vault:v1:base64signature).
    /// </summary>
    public required string Signature { get; init; }

    /// <summary>
    /// The key version used for signing.
    /// </summary>
    public required int KeyVersion { get; init; }

    /// <summary>
    /// Gets the raw signature bytes (without the vault:vN: prefix).
    /// </summary>
    public byte[] GetSignatureBytes()
    {
        var parts = Signature.Split(':');
        if (parts.Length >= 3)
        {
            return System.Convert.FromBase64String(parts[2]);
        }
        return System.Convert.FromBase64String(Signature);
    }
}

/// <summary>
/// Request to verify a signature with the Transit engine.
/// </summary>
public sealed record TransitVerifyRequest
{
    /// <summary>
    /// The name of the signing key in Vault.
    /// </summary>
    public required string KeyName { get; init; }

    /// <summary>
    /// The original data that was signed.
    /// </summary>
    public required byte[] Data { get; init; }

    /// <summary>
    /// The signature to verify.
    /// </summary>
    public required string Signature { get; init; }

    /// <summary>
    /// The hash algorithm used.
    /// </summary>
    public TransitHashAlgorithm HashAlgorithm { get; init; } = TransitHashAlgorithm.Sha256;

    /// <summary>
    /// The signature algorithm for RSA keys.
    /// </summary>
    public TransitSignatureAlgorithm SignatureAlgorithm { get; init; } = TransitSignatureAlgorithm.Pss;

    /// <summary>
    /// If true, the data is already hashed.
    /// </summary>
    public bool Prehashed { get; init; }

    /// <summary>
    /// Optional context for derived keys.
    /// </summary>
    public byte[]? Context { get; init; }

    /// <summary>
    /// Marshaling algorithm for ECDSA signatures.
    /// </summary>
    public TransitMarshalingAlgorithm? MarshalingAlgorithm { get; init; }
}

/// <summary>
/// Information about a Transit key.
/// </summary>
public sealed record TransitKeyInfo
{
    /// <summary>
    /// The key name.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// The key type (e.g., "aes256-gcm96", "rsa-2048").
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The latest key version.
    /// </summary>
    public required int LatestVersion { get; init; }

    /// <summary>
    /// Minimum version allowed for decryption.
    /// </summary>
    public required int MinDecryptionVersion { get; init; }

    /// <summary>
    /// Minimum version allowed for encryption.
    /// </summary>
    public required int MinEncryptionVersion { get; init; }

    /// <summary>
    /// Whether the key supports derivation.
    /// </summary>
    public required bool SupportsDrivation { get; init; }

    /// <summary>
    /// Whether the key is exportable.
    /// </summary>
    public required bool Exportable { get; init; }

    /// <summary>
    /// Whether deletion is allowed.
    /// </summary>
    public required bool DeletionAllowed { get; init; }
}

/// <summary>
/// Hash algorithms supported by Transit.
/// </summary>
public enum TransitHashAlgorithm
{
    /// <summary>SHA-1 (not recommended for security).</summary>
    Sha1,
    /// <summary>SHA-224.</summary>
    Sha224,
    /// <summary>SHA-256 (recommended).</summary>
    Sha256,
    /// <summary>SHA-384.</summary>
    Sha384,
    /// <summary>SHA-512.</summary>
    Sha512
}

/// <summary>
/// Signature algorithms for RSA keys.
/// </summary>
public enum TransitSignatureAlgorithm
{
    /// <summary>
    /// RSASSA-PSS (recommended).
    /// </summary>
    Pss,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 (legacy compatibility).
    /// </summary>
    Pkcs1v15
}

/// <summary>
/// Marshaling algorithms for ECDSA signatures.
/// </summary>
public enum TransitMarshalingAlgorithm
{
    /// <summary>
    /// ASN.1 DER format (default).
    /// </summary>
    Asn1,

    /// <summary>
    /// JWS format.
    /// </summary>
    Jws
}

/// <summary>
/// Output format for hash and random operations.
/// </summary>
public enum TransitOutputFormat
{
    /// <summary>Base64 encoded output.</summary>
    Base64,
    /// <summary>Hexadecimal encoded output.</summary>
    Hex
}

// ==================== PKI Engine Models ====================

/// <summary>
/// Request to issue a certificate from the PKI engine.
/// </summary>
public sealed record PkiCertificateRequest
{
    /// <summary>
    /// The PKI role to use for issuance.
    /// </summary>
    public required string RoleName { get; init; }

    /// <summary>
    /// The common name for the certificate.
    /// </summary>
    public required string CommonName { get; init; }

    /// <summary>
    /// Subject Alternative Names (DNS names).
    /// </summary>
    public IReadOnlyList<string>? AltNames { get; init; }

    /// <summary>
    /// IP Subject Alternative Names.
    /// </summary>
    public IReadOnlyList<string>? IpSans { get; init; }

    /// <summary>
    /// URI Subject Alternative Names.
    /// </summary>
    public IReadOnlyList<string>? UriSans { get; init; }

    /// <summary>
    /// Certificate TTL (e.g., "720h" for 30 days).
    /// </summary>
    public string? Ttl { get; init; }

    /// <summary>
    /// Format: "pem", "der", or "pem_bundle".
    /// </summary>
    public string Format { get; init; } = "pem";

    /// <summary>
    /// Private key format: "der" or "pkcs8".
    /// </summary>
    public string PrivateKeyFormat { get; init; } = "der";

    /// <summary>
    /// Whether to exclude the CN from SANs.
    /// </summary>
    public bool ExcludeCnFromSans { get; init; }
}

/// <summary>
/// Response from issuing a PKI certificate.
/// </summary>
public sealed record PkiCertificateResponse
{
    /// <summary>
    /// The issued certificate in PEM format.
    /// </summary>
    public required string Certificate { get; init; }

    /// <summary>
    /// The private key (only returned if generated by Vault).
    /// </summary>
    public string? PrivateKey { get; init; }

    /// <summary>
    /// The private key type.
    /// </summary>
    public string? PrivateKeyType { get; init; }

    /// <summary>
    /// The certificate serial number.
    /// </summary>
    public required string SerialNumber { get; init; }

    /// <summary>
    /// The issuing CA certificate.
    /// </summary>
    public string? IssuingCa { get; init; }

    /// <summary>
    /// The full certificate chain.
    /// </summary>
    public IReadOnlyList<string>? CaChain { get; init; }

    /// <summary>
    /// When the certificate expires.
    /// </summary>
    public required System.DateTimeOffset Expiration { get; init; }
}
