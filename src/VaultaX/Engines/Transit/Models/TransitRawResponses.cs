using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VaultaX.Engines.Transit.Models;

/// <summary>
/// Raw response shape for <c>GET /transit/export/certificate-chain/:name(/:version)</c>.
/// </summary>
internal sealed class TransitExportCertResponse
{
    /// <summary>The data payload returned by Vault.</summary>
    [JsonPropertyName("data")]
    public TransitExportCertData? Data { get; set; }
}

/// <summary>
/// Inner <c>data</c> node for the certificate-chain export endpoint.
/// </summary>
internal sealed class TransitExportCertData
{
    /// <summary>
    /// Map of key version (as string) to PEM certificate chain string.
    /// </summary>
    [JsonPropertyName("keys")]
    public Dictionary<string, string>? Keys { get; set; }

    /// <summary>The key name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>The key type.</summary>
    [JsonPropertyName("type")]
    public string? Type { get; set; }
}

/// <summary>
/// Raw response shape for <c>GET /transit/keys/:name</c>, used to extract the
/// <c>certificate_chain</c> field that is not cleanly exposed by VaultSharp.
/// </summary>
internal sealed class TransitKeyReadResponse
{
    /// <summary>The data payload returned by Vault.</summary>
    [JsonPropertyName("data")]
    public TransitKeyReadData? Data { get; set; }
}

/// <summary>
/// Inner <c>data</c> node for the read-key endpoint — only fields VaultaX extracts beyond VaultSharp are declared.
/// </summary>
internal sealed class TransitKeyReadData
{
    /// <summary>
    /// PEM-encoded certificate chain associated with the key, or <c>null</c>.
    /// </summary>
    [JsonPropertyName("certificate_chain")]
    public string? CertificateChain { get; set; }
}

/// <summary>
/// Empty response marker used for raw POST calls whose response body is not consumed.
/// </summary>
internal sealed class TransitRawVoidResponse
{
}
