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
using VaultaX.Configuration;
using VaultaX.Extensions;

// ============================================================================
// VaultaX Sample WebAPI
// ============================================================================
// This sample demonstrates how to use VaultaX in an ASP.NET Core application.
// It shows:
// 1. Configuration loading from Vault (secrets override appsettings)
// 2. DI registration of VaultaX services
// 3. Health checks integration
// 4. Using Transit engine for signing/encryption
// 5. Using KV engine for reading secrets
//
// TWO CONFIGURATION APPROACHES:
// - OPTION A: AppSettings (appsettings.json) - Currently active
// - OPTION B: Fluent API (code) - Comment out Option A and uncomment Option B
// ============================================================================

var builder = WebApplication.CreateBuilder(args);

// ============================================================================
// OPTION A: Configuration via appsettings.json (ACTIVE)
// ============================================================================
// All configuration is in appsettings.json under the "VaultaX" section.
// This is the recommended approach for most scenarios as it allows
// configuration changes without recompilation.
// ============================================================================

// Step 1: Add VaultaX as a configuration source
builder.Configuration.AddVaultaX();

// Step 2: Register VaultaX services from configuration
builder.Services.AddVaultaX(builder.Configuration);

// ============================================================================
// OPTION B: Configuration via Fluent API (COMMENTED OUT)
// ============================================================================
// Uncomment this section and comment out Option A to use Fluent API.
// All configuration is done in code, useful for dynamic configuration.
// ============================================================================

/*
// Step 1: Add VaultaX as a configuration source with Fluent API
builder.Configuration.AddVaultaX(options =>
{
    options.Enabled = true;
    options.Address = "http://localhost:8200";
    options.MountPoint = "secret";
    options.KvVersion = 2;
    options.BasePath = "development";

    // Authentication - Token method (simplest for development)
    options.Authentication.Method = "Token";
    options.Authentication.Token = "VAULT_TOKEN"; // Reads from env var

    // Alternative: AppRole (recommended for production)
    // options.Authentication.Method = "AppRole";
    // options.Authentication.RoleId = "my-role-id";
    // options.Authentication.SecretId = "VAULT_SECRET_ID";

    // Alternative: Kubernetes
    // options.Authentication.Method = "Kubernetes";
    // options.Authentication.Role = "my-k8s-role";
    // options.Authentication.ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    // Alternative: LDAP/UserPass
    // options.Authentication.Method = "LDAP"; // or "UserPass"
    // options.Authentication.Username = "myuser";
    // options.Authentication.Password = "VAULT_PASSWORD";

    // Alternative: JWT
    // options.Authentication.Method = "JWT";
    // options.Authentication.Role = "my-jwt-role";
    // options.Authentication.Token = "JWT_TOKEN";

    // Alternative: AWS
    // options.Authentication.Method = "AWS";
    // options.Authentication.Role = "my-aws-role";
    // options.Authentication.Region = "us-east-1";
    // options.Authentication.AuthType = "iam";

    // Alternative: Azure
    // options.Authentication.Method = "Azure";
    // options.Authentication.Role = "my-azure-role";
    // options.Authentication.Resource = "https://management.azure.com/";

    // Alternative: GitHub
    // options.Authentication.Method = "GitHub";
    // options.Authentication.Token = "GITHUB_TOKEN";

    // Alternative: Certificate
    // options.Authentication.Method = "Certificate";
    // options.Authentication.CertificatePath = "/path/to/cert.pfx";
    // options.Authentication.CertificatePassword = "CERT_PASSWORD";
    // options.Authentication.Role = "my-cert-role";

    // Alternative: RADIUS
    // options.Authentication.Method = "RADIUS";
    // options.Authentication.Username = "myuser";
    // options.Authentication.Password = "RADIUS_PASSWORD";

    // Alternative: Custom
    // options.Authentication.Method = "Custom";
    // options.Authentication.CustomPath = "auth/custom/login";
    // options.Authentication.CustomValue = "CUSTOM_AUTH_TOKEN";

    // Secret mappings - map Vault secrets to configuration keys
    options.Mappings.Add(new SecretMappingOptions
    {
        SecretPath = "database",
        Bindings = new()
        {
            ["connectionString"] = "ConnectionStrings:DefaultConnection",
            ["password"] = "Database:Password"
        }
    });

    options.Mappings.Add(new SecretMappingOptions
    {
        SecretPath = "rabbitmq",
        Bindings = new()
        {
            ["host"] = "RabbitMQ:Host",
            ["username"] = "RabbitMQ:Username",
            ["password"] = "RabbitMQ:Password",
            ["virtualHost"] = "RabbitMQ:VirtualHost"
        }
    });

    options.Mappings.Add(new SecretMappingOptions
    {
        SecretPath = "jwt",
        Bindings = new()
        {
            ["secret"] = "Jwt:Secret",
            ["issuer"] = "Jwt:Issuer",
            ["audience"] = "Jwt:Audience"
        }
    });

    // Reload configuration - periodically check for secret changes
    options.Reload.Enabled = true;
    options.Reload.IntervalSeconds = 300;

    // Token renewal - automatically renew token before expiration
    options.TokenRenewal.Enabled = true;
    options.TokenRenewal.CheckIntervalSeconds = 60;
    options.TokenRenewal.ThresholdPercent = 75;
    options.TokenRenewal.MaxConsecutiveFailures = 3;
});

// Step 2: Register VaultaX services with Fluent API
builder.Services.AddVaultaX(options =>
{
    options.Enabled = true;
    options.Address = "http://localhost:8200";
    options.MountPoint = "secret";
    options.KvVersion = 2;
    options.BasePath = "development";

    options.Authentication.Method = "Token";
    options.Authentication.Token = "VAULT_TOKEN";

    options.Mappings.Add(new SecretMappingOptions
    {
        SecretPath = "database",
        Bindings = new()
        {
            ["connectionString"] = "ConnectionStrings:DefaultConnection",
            ["password"] = "Database:Password"
        }
    });

    options.Reload.Enabled = true;
    options.Reload.IntervalSeconds = 300;

    options.TokenRenewal.Enabled = true;
    options.TokenRenewal.CheckIntervalSeconds = 60;
});
*/

// ============================================================================
// Health Checks
// ============================================================================
builder.Services.AddHealthChecks()
    .AddVaultaX("vault", tags: ["ready", "live"]);

builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

app.UseHttpsRedirection();
app.MapHealthChecks("/health");

// ============================================================================
// Sample Endpoints
// ============================================================================

// Get configuration value (may come from Vault)
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

// Read secret from Vault KV engine
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
            warning = "Never expose secrets in production APIs"
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to read secret: {ex.Message}");
    }
})
.WithName("GetSecret")
.WithDescription("Reads a secret from Vault KV engine (demo only)");

// Sign data using Transit engine
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
.WithDescription("Signs data using Vault Transit engine");

// Verify signature using Transit engine
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

        return Results.Ok(new { valid = isValid, keyName = request.KeyName });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to verify signature: {ex.Message}");
    }
})
.WithName("VerifySignature")
.WithDescription("Verifies a signature using Vault Transit engine");

// Encrypt data using Transit engine
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

        return Results.Ok(new { ciphertext, keyName = request.KeyName });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to encrypt data: {ex.Message}");
    }
})
.WithName("EncryptData")
.WithDescription("Encrypts data using Vault Transit engine");

// Decrypt data using Transit engine
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

// Get Vault client status
app.MapGet("/vault/status", ([FromServices] IVaultClient? vaultClient) =>
{
    if (vaultClient == null)
    {
        return Results.Ok(new { enabled = false, message = "VaultaX is not configured" });
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

public record SignRequest(string KeyName, string Data, string? HashAlgorithm = null);
public record VerifyRequest(string KeyName, string Data, string Signature, string? HashAlgorithm = null);
public record EncryptRequest(string KeyName, string Plaintext);
public record DecryptRequest(string KeyName, string Ciphertext);
