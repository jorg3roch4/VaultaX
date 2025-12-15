using System;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using VaultaX.Abstractions;
using VaultaX.Extensions;

// ============================================================================
// VaultaX Sample WebAPI
// ============================================================================
// This sample demonstrates how to use VaultaX in an ASP.NET Core application.
// It shows:
// 1. Configuration loading from Vault (secrets override appsettings)
// 2. DI registration of VaultaX services
// 3. Health checks integration
// 4. Using Transit engine for signing
// 5. Using KV engine for reading secrets
// ============================================================================

var builder = WebApplication.CreateBuilder(args);

// Step 1: Add VaultaX as a configuration source
// This will read secrets from Vault and overlay them onto appsettings.json values
// If Vault is disabled (VaultaX:Enabled = false), this does nothing
builder.Configuration.AddVaultaX();

// Step 2: Register VaultaX services
// This adds IVaultClient, IKeyValueEngine, ITransitEngine, IPkiEngine
// Also registers background services for token renewal and secret change detection
builder.Services.AddVaultaX(builder.Configuration);

// Step 3: Add health checks with VaultaX
builder.Services.AddHealthChecks()
    .AddVaultaX("vault", tags: ["ready", "live"]);

// Add API documentation (endpoints explorer for minimal APIs)
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Configure the HTTP request pipeline

app.UseHttpsRedirection();

// Map health check endpoint
app.MapHealthChecks("/health");

// ============================================================================
// Sample Endpoints
// ============================================================================

// Endpoint: Get current configuration value
// Demonstrates how secrets from Vault override appsettings.json
app.MapGet("/config/{key}", (string key, IConfiguration configuration) =>
{
    var value = configuration[key];
    if (string.IsNullOrEmpty(value))
    {
        return Results.NotFound($"Configuration key '{key}' not found");
    }
    return Results.Ok(new { key, value });
})
.WithName("GetConfiguration")
.WithDescription("Gets a configuration value (may come from Vault if configured)");

// Endpoint: Read a secret directly from Vault KV engine
app.MapGet("/secrets/{path}", async (string path, [FromServices] IKeyValueEngine? kvEngine) =>
{
    if (kvEngine == null)
    {
        return Results.Problem("VaultaX is not configured or enabled");
    }

    try
    {
        var secret = await kvEngine.ReadAsync(path);
        return Results.Ok(new
        {
            path,
            keys = secret.Keys.ToList(),
            // Don't expose actual values in production!
            warning = "Never expose secrets in production APIs"
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to read secret: {ex.Message}");
    }
})
.WithName("GetSecret")
.WithDescription("Reads a secret from Vault KV engine (for demo purposes only)");

// Endpoint: Sign data using Transit engine
app.MapPost("/sign", async (SignRequest request, [FromServices] ITransitEngine? transitEngine) =>
{
    if (transitEngine == null)
    {
        return Results.Problem("VaultaX Transit engine is not configured");
    }

    try
    {
        var hashAlgorithm = request.HashAlgorithm != null
            ? Enum.Parse<TransitHashAlgorithm>(request.HashAlgorithm, ignoreCase: true)
            : TransitHashAlgorithm.Sha256;

        var response = await transitEngine.SignAsync(new TransitSignRequest
        {
            KeyName = request.KeyName,
            Data = Encoding.UTF8.GetBytes(request.Data),
            HashAlgorithm = hashAlgorithm
        });

        return Results.Ok(new
        {
            signature = response.Signature,
            keyVersion = response.KeyVersion,
            keyName = request.KeyName
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to sign data: {ex.Message}");
    }
})
.WithName("SignData")
.WithDescription("Signs data using Vault Transit engine - private key never leaves Vault");

// Endpoint: Verify a signature using Transit engine
app.MapPost("/verify", async (VerifyRequest request, [FromServices] ITransitEngine? transitEngine) =>
{
    if (transitEngine == null)
    {
        return Results.Problem("VaultaX Transit engine is not configured");
    }

    try
    {
        var hashAlgorithm = request.HashAlgorithm != null
            ? Enum.Parse<TransitHashAlgorithm>(request.HashAlgorithm, ignoreCase: true)
            : TransitHashAlgorithm.Sha256;

        var isValid = await transitEngine.VerifyAsync(new TransitVerifyRequest
        {
            KeyName = request.KeyName,
            Data = Encoding.UTF8.GetBytes(request.Data),
            Signature = request.Signature,
            HashAlgorithm = hashAlgorithm
        });

        return Results.Ok(new
        {
            valid = isValid,
            keyName = request.KeyName
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to verify signature: {ex.Message}");
    }
})
.WithName("VerifySignature")
.WithDescription("Verifies a signature using Vault Transit engine");

// Endpoint: Encrypt data using Transit engine
app.MapPost("/encrypt", async (EncryptRequest request, [FromServices] ITransitEngine? transitEngine) =>
{
    if (transitEngine == null)
    {
        return Results.Problem("VaultaX Transit engine is not configured");
    }

    try
    {
        var ciphertext = await transitEngine.EncryptAsync(
            request.KeyName,
            Encoding.UTF8.GetBytes(request.Plaintext));

        return Results.Ok(new
        {
            ciphertext,
            keyName = request.KeyName
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to encrypt data: {ex.Message}");
    }
})
.WithName("EncryptData")
.WithDescription("Encrypts data using Vault Transit engine");

// Endpoint: Decrypt data using Transit engine
app.MapPost("/decrypt", async (DecryptRequest request, [FromServices] ITransitEngine? transitEngine) =>
{
    if (transitEngine == null)
    {
        return Results.Problem("VaultaX Transit engine is not configured");
    }

    try
    {
        var plaintext = await transitEngine.DecryptAsync(request.KeyName, request.Ciphertext);
        return Results.Ok(new
        {
            plaintext = Encoding.UTF8.GetString(plaintext),
            keyName = request.KeyName
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to decrypt data: {ex.Message}");
    }
})
.WithName("DecryptData")
.WithDescription("Decrypts data using Vault Transit engine");

// Endpoint: Show Vault client status
app.MapGet("/vault/status", ([FromServices] IVaultClient? vaultClient) =>
{
    if (vaultClient == null)
    {
        return Results.Ok(new
        {
            enabled = false,
            message = "VaultaX is not configured"
        });
    }

    return Results.Ok(new
    {
        enabled = true,
        authenticated = vaultClient.IsAuthenticated,
        tokenTtl = vaultClient.TokenTimeToLive?.ToString() ?? "N/A",
        tokenRenewable = vaultClient.IsTokenRenewable
    });
})
.WithName("GetVaultStatus")
.WithDescription("Gets the current VaultaX client status");

app.Run();

// ============================================================================
// Request/Response Models
// ============================================================================

/// <summary>
/// Request model for signing data.
/// </summary>
public record SignRequest(string KeyName, string Data, string? HashAlgorithm = null);

/// <summary>
/// Request model for verifying signatures.
/// </summary>
public record VerifyRequest(string KeyName, string Data, string Signature, string? HashAlgorithm = null);

/// <summary>
/// Request model for encrypting data.
/// </summary>
public record EncryptRequest(string KeyName, string Plaintext);

/// <summary>
/// Request model for decrypting data.
/// </summary>
public record DecryptRequest(string KeyName, string Ciphertext);
