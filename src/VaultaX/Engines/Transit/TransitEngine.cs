using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using VaultaX.Exceptions;
using VaultSharpTransit = VaultSharp.V1.SecretsEngines.Transit;

namespace VaultaX.Engines.Transit;

/// <summary>
/// Implementation of the Transit secrets engine for encryption and signing operations.
/// The Transit engine provides cryptographic operations without exposing keys.
/// </summary>
public sealed class TransitEngine : Abstractions.ITransitEngine
{
    private readonly Abstractions.IVaultClient _vaultClient;
    private readonly string _mountPoint;
    private readonly ILogger<TransitEngine>? _logger;

    /// <summary>
    /// Creates a new Transit engine instance.
    /// </summary>
    /// <param name="vaultClient">The Vault client.</param>
    /// <param name="mountPoint">The mount point for the Transit engine (default: "transit").</param>
    /// <param name="logger">Optional logger.</param>
    public TransitEngine(
        Abstractions.IVaultClient vaultClient,
        string mountPoint = "transit",
        ILogger<TransitEngine>? logger = null)
    {
        _vaultClient = vaultClient ?? throw new ArgumentNullException(nameof(vaultClient));
        _mountPoint = mountPoint ?? "transit";
        _logger = logger;
    }

    /// <inheritdoc />
    public string EngineType => "transit";

    /// <inheritdoc />
    public string MountPoint => _mountPoint;

    /// <inheritdoc />
    public async Task<string> EncryptAsync(
        string keyName,
        byte[] plaintext,
        byte[]? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(plaintext);

        _logger?.LogDebug("Encrypting data with key {KeyName}", keyName);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var base64Plaintext = Convert.ToBase64String(plaintext);
            var base64Context = context != null ? Convert.ToBase64String(context) : null;

            var result = await client.V1.Secrets.Transit.EncryptAsync(
                keyName: keyName,
                encryptRequestOptions: new VaultSharpTransit.EncryptRequestOptions
                {
                    Base64EncodedPlainText = base64Plaintext,
                    Base64EncodedContext = base64Context
                },
                mountPoint: _mountPoint).ConfigureAwait(false);

            _logger?.LogDebug("Data encrypted successfully with key {KeyName}", keyName);
            return result.Data.CipherText;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to encrypt data with key {KeyName}", keyName);
            throw new VaultTransitException($"Encryption failed: {ex.Message}", "encrypt", keyName, ex);
        }
    }

    /// <inheritdoc />
    public async Task<byte[]> DecryptAsync(
        string keyName,
        string ciphertext,
        byte[]? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentException.ThrowIfNullOrWhiteSpace(ciphertext);

        _logger?.LogDebug("Decrypting data with key {KeyName}", keyName);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var base64Context = context != null ? Convert.ToBase64String(context) : null;

            var result = await client.V1.Secrets.Transit.DecryptAsync(
                keyName: keyName,
                decryptRequestOptions: new VaultSharpTransit.DecryptRequestOptions
                {
                    CipherText = ciphertext,
                    Base64EncodedContext = base64Context
                },
                mountPoint: _mountPoint).ConfigureAwait(false);

            _logger?.LogDebug("Data decrypted successfully with key {KeyName}", keyName);
            return Convert.FromBase64String(result.Data.Base64EncodedPlainText);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to decrypt data with key {KeyName}", keyName);
            throw new VaultTransitException($"Decryption failed: {ex.Message}", "decrypt", keyName, ex);
        }
    }

    /// <inheritdoc />
    public async Task<Abstractions.TransitSignResponse> SignAsync(
        Abstractions.TransitSignRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.KeyName);
        ArgumentNullException.ThrowIfNull(request.Data);

        _logger?.LogDebug(
            "Signing data with key {KeyName}, algorithm: {HashAlgorithm}/{SignatureAlgorithm}",
            request.KeyName,
            request.HashAlgorithm,
            request.SignatureAlgorithm);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var base64Input = Convert.ToBase64String(request.Data);
            var base64Context = request.Context != null ? Convert.ToBase64String(request.Context) : null;

            var signOptions = new VaultSharpTransit.SignRequestOptions
            {
                Base64EncodedInput = base64Input,
                Base64EncodedKeyDerivationContext = base64Context,
                HashAlgorithm = MapHashAlgorithm(request.HashAlgorithm),
                SignatureAlgorithm = MapSignatureAlgorithm(request.SignatureAlgorithm),
                PreHashed = request.Prehashed,
                KeyVersion = request.KeyVersion
            };

            if (request.MarshalingAlgorithm.HasValue)
            {
                signOptions.MarshalingAlgorithm = MapMarshalingAlgorithm(request.MarshalingAlgorithm.Value);
            }

            var result = await client.V1.Secrets.Transit.SignDataAsync(
                keyName: request.KeyName,
                signOptions: signOptions,
                mountPoint: _mountPoint).ConfigureAwait(false);

            _logger?.LogInformation(
                "Data signed successfully with key {KeyName}, version: {KeyVersion}",
                request.KeyName,
                result.Data.KeyVersion);

            return new Abstractions.TransitSignResponse
            {
                Signature = result.Data.Signature,
                KeyVersion = result.Data.KeyVersion ?? 0
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to sign data with key {KeyName}", request.KeyName);
            throw new VaultTransitException($"Signing failed: {ex.Message}", "sign", request.KeyName, ex);
        }
    }

    /// <inheritdoc />
    public async Task<bool> VerifyAsync(
        Abstractions.TransitVerifyRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.KeyName);
        ArgumentNullException.ThrowIfNull(request.Data);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Signature);

        _logger?.LogDebug("Verifying signature with key {KeyName}", request.KeyName);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var base64Input = Convert.ToBase64String(request.Data);
            var base64Context = request.Context != null ? Convert.ToBase64String(request.Context) : null;

            var verifyOptions = new VaultSharpTransit.VerifyRequestOptions
            {
                Base64EncodedInput = base64Input,
                Base64EncodedKeyDerivationContext = base64Context,
                Signature = request.Signature,
                HashAlgorithm = MapHashAlgorithm(request.HashAlgorithm),
                SignatureAlgorithm = MapSignatureAlgorithm(request.SignatureAlgorithm),
                PreHashed = request.Prehashed
            };

            if (request.MarshalingAlgorithm.HasValue)
            {
                verifyOptions.MarshalingAlgorithm = MapMarshalingAlgorithm(request.MarshalingAlgorithm.Value);
            }

            var result = await client.V1.Secrets.Transit.VerifySignedDataAsync(
                keyName: request.KeyName,
                verifyOptions: verifyOptions,
                mountPoint: _mountPoint).ConfigureAwait(false);

            var isValid = result.Data.Valid;
            _logger?.LogDebug("Signature verification result for key {KeyName}: {IsValid}", request.KeyName, isValid);

            return isValid;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to verify signature with key {KeyName}", request.KeyName);
            throw new VaultTransitException($"Verification failed: {ex.Message}", "verify", request.KeyName, ex);
        }
    }

    /// <inheritdoc />
    public async Task<string> HashAsync(
        byte[] data,
        Abstractions.TransitHashAlgorithm algorithm = Abstractions.TransitHashAlgorithm.Sha256,
        Abstractions.TransitOutputFormat format = Abstractions.TransitOutputFormat.Base64,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);

        _logger?.LogDebug("Generating hash with algorithm {Algorithm}", algorithm);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var base64Input = Convert.ToBase64String(data);

            var result = await client.V1.Secrets.Transit.HashDataAsync(
                hashOptions: new VaultSharpTransit.HashRequestOptions
                {
                    Base64EncodedInput = base64Input,
                    Algorithm = MapHashAlgorithm(algorithm),
                    Format = format == Abstractions.TransitOutputFormat.Hex
                        ? VaultSharpTransit.OutputEncodingFormat.hex
                        : VaultSharpTransit.OutputEncodingFormat.base64
                },
                mountPoint: _mountPoint).ConfigureAwait(false);

            return result.Data.HashSum;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate hash");
            throw new VaultTransitException($"Hash generation failed: {ex.Message}", "hash", null, ex);
        }
    }

    /// <inheritdoc />
    public async Task<string> HmacAsync(
        string keyName,
        byte[] data,
        Abstractions.TransitHashAlgorithm algorithm = Abstractions.TransitHashAlgorithm.Sha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(data);

        _logger?.LogDebug("Generating HMAC with key {KeyName}", keyName);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var base64Input = Convert.ToBase64String(data);

            var result = await client.V1.Secrets.Transit.GenerateHmacAsync(
                keyName: keyName,
                hmacOptions: new VaultSharpTransit.HmacRequestOptions
                {
                    Base64EncodedInput = base64Input,
                    Algorithm = MapHashAlgorithm(algorithm)
                },
                mountPoint: _mountPoint).ConfigureAwait(false);

            return result.Data.Hmac;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate HMAC with key {KeyName}", keyName);
            throw new VaultTransitException($"HMAC generation failed: {ex.Message}", "hmac", keyName, ex);
        }
    }

    /// <inheritdoc />
    public async Task<string> GenerateRandomBytesAsync(
        int byteCount,
        Abstractions.TransitOutputFormat format = Abstractions.TransitOutputFormat.Base64,
        CancellationToken cancellationToken = default)
    {
        if (byteCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(byteCount), "Byte count must be positive");

        _logger?.LogDebug("Generating {ByteCount} random bytes", byteCount);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();

            var result = await client.V1.Secrets.Transit.GenerateRandomBytesAsync(
                randomOptions: new VaultSharpTransit.RandomBytesRequestOptions
                {
                    BytesToGenerate = byteCount,
                    Format = format == Abstractions.TransitOutputFormat.Hex
                        ? VaultSharpTransit.OutputEncodingFormat.hex
                        : VaultSharpTransit.OutputEncodingFormat.base64
                },
                mountPoint: _mountPoint).ConfigureAwait(false);

            return result.Data.EncodedRandomBytes;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate random bytes");
            throw new VaultTransitException($"Random byte generation failed: {ex.Message}", "random", null, ex);
        }
    }

    /// <inheritdoc />
    public async Task<Abstractions.TransitKeyInfo?> GetKeyInfoAsync(
        string keyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);

        _logger?.LogDebug("Getting key info for {KeyName}", keyName);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();

            var result = await client.V1.Secrets.Transit.ReadEncryptionKeyAsync(
                keyName: keyName,
                mountPoint: _mountPoint).ConfigureAwait(false);

            if (result?.Data == null)
                return null;

            return new Abstractions.TransitKeyInfo
            {
                Name = result.Data.Name,
                Type = result.Data.Type.ToString(),
                LatestVersion = result.Data.LatestVersion,
                MinDecryptionVersion = result.Data.MinimumDecryptionVersion,
                MinEncryptionVersion = result.Data.MinimumEncryptionVersion,
                SupportsDrivation = result.Data.SupportsDerivation,
                Exportable = result.Data.Exportable,
                DeletionAllowed = result.Data.DeletionAllowed
            };
        }
        catch (VaultSharp.Core.VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get key info for {KeyName}", keyName);
            throw new VaultTransitException($"Failed to get key info: {ex.Message}", "read-key", keyName, ex);
        }
    }

    /// <inheritdoc />
    public async Task<string> RewrapAsync(
        string keyName,
        string ciphertext,
        byte[]? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentException.ThrowIfNullOrWhiteSpace(ciphertext);

        _logger?.LogDebug("Rewrapping ciphertext with key {KeyName}", keyName);

        try
        {
            var client = _vaultClient.GetUnderlyingClient();
            var base64Context = context != null ? Convert.ToBase64String(context) : null;

            var result = await client.V1.Secrets.Transit.RewrapAsync(
                keyName: keyName,
                rewrapRequestOptions: new VaultSharpTransit.RewrapRequestOptions
                {
                    CipherText = ciphertext,
                    Base64EncodedContext = base64Context
                },
                mountPoint: _mountPoint).ConfigureAwait(false);

            _logger?.LogInformation("Ciphertext rewrapped successfully with key {KeyName}", keyName);
            return result.Data.CipherText;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to rewrap ciphertext with key {KeyName}", keyName);
            throw new VaultTransitException($"Rewrap failed: {ex.Message}", "rewrap", keyName, ex);
        }
    }

    private static VaultSharpTransit.TransitHashAlgorithm MapHashAlgorithm(Abstractions.TransitHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            Abstractions.TransitHashAlgorithm.Sha1 => VaultSharpTransit.TransitHashAlgorithm.SHA2_256, // SHA1 is obsolete, using SHA256 instead
            Abstractions.TransitHashAlgorithm.Sha224 => VaultSharpTransit.TransitHashAlgorithm.SHA2_224,
            Abstractions.TransitHashAlgorithm.Sha256 => VaultSharpTransit.TransitHashAlgorithm.SHA2_256,
            Abstractions.TransitHashAlgorithm.Sha384 => VaultSharpTransit.TransitHashAlgorithm.SHA2_384,
            Abstractions.TransitHashAlgorithm.Sha512 => VaultSharpTransit.TransitHashAlgorithm.SHA2_512,
            _ => VaultSharpTransit.TransitHashAlgorithm.SHA2_256
        };
    }

    private static VaultSharpTransit.SignatureAlgorithm MapSignatureAlgorithm(Abstractions.TransitSignatureAlgorithm algorithm)
    {
        return algorithm switch
        {
            Abstractions.TransitSignatureAlgorithm.Pss => VaultSharpTransit.SignatureAlgorithm.pss,
            Abstractions.TransitSignatureAlgorithm.Pkcs1v15 => VaultSharpTransit.SignatureAlgorithm.pkcs1v15,
            _ => VaultSharpTransit.SignatureAlgorithm.pss
        };
    }

    private static VaultSharpTransit.MarshalingAlgorithm MapMarshalingAlgorithm(Abstractions.TransitMarshalingAlgorithm algorithm)
    {
        return algorithm switch
        {
            Abstractions.TransitMarshalingAlgorithm.Asn1 => VaultSharpTransit.MarshalingAlgorithm.asn1,
            Abstractions.TransitMarshalingAlgorithm.Jws => VaultSharpTransit.MarshalingAlgorithm.jws,
            _ => VaultSharpTransit.MarshalingAlgorithm.asn1
        };
    }
}
