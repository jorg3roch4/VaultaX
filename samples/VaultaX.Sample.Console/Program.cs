using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Spectre.Console;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultaX.Extensions;

namespace VaultaX.Sample.Console;

// ============================================================================
// VaultaX Sample Console Application
// ============================================================================
// This sample demonstrates VaultaX usage for:
// 1. Reading secrets from Key-Value engine
// 2. Signing data with Transit engine (private key never leaves Vault)
// 3. Verifying signatures
//
// TWO CONFIGURATION APPROACHES:
// - OPTION A: AppSettings (appsettings.json) - Currently active
// - OPTION B: Fluent API (code) - Comment out Option A and uncomment Option B
// ============================================================================

internal class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            AnsiConsole.Write(
                new FigletText("VaultaX Sample")
                    .LeftJustified()
                    .Color(Color.Blue));

            AnsiConsole.MarkupLine("[green]VaultaX - HashiCorp Vault Integration for .NET[/]");
            AnsiConsole.WriteLine();

            var host = CreateHostBuilder(args).Build();

            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                await RunSampleAsync(services);
            }

            return 0;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
            AnsiConsole.WriteException(ex);
            return 1;
        }
    }

    // ========================================================================
    // OPTION A: Configuration via appsettings.json (ACTIVE)
    // ========================================================================
    // All configuration is in appsettings.json under the "VaultaX" section.
    // ========================================================================
    private static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((context, config) =>
            {
                config
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .AddJsonFile($"appsettings.{context.HostingEnvironment.EnvironmentName}.json", optional: true)
                    .AddEnvironmentVariables();
            })
            .ConfigureServices((context, services) =>
            {
                // Register VaultaX services from configuration
                services.AddVaultaX(context.Configuration);
            });

    // ========================================================================
    // OPTION B: Configuration via Fluent API (COMMENTED OUT)
    // ========================================================================
    // Uncomment this method and comment out Option A to use Fluent API.
    // ========================================================================
    /*
    private static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((context, config) =>
            {
                config
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .AddEnvironmentVariables();
            })
            .ConfigureServices((context, services) =>
            {
                // Register VaultaX services with Fluent API
                services.AddVaultaX(options =>
                {
                    options.Enabled = true;
                    options.Address = "http://localhost:8200";
                    options.MountPoint = "secret";
                    options.KvVersion = 2;
                    options.BasePath = "";

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

                    // Alternative: LDAP/UserPass
                    // options.Authentication.Method = "LDAP";
                    // options.Authentication.Username = "myuser";
                    // options.Authentication.Password = "VAULT_LDAP_PASSWORD";

                    // Alternative: JWT
                    // options.Authentication.Method = "JWT";
                    // options.Authentication.Role = "my-jwt-role";
                    // options.Authentication.Token = "JWT_TOKEN";

                    // Alternative: AWS
                    // options.Authentication.Method = "AWS";
                    // options.Authentication.Role = "my-aws-role";
                    // options.Authentication.Region = "us-east-1";

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

                    // Secret mappings (optional for console app)
                    options.Mappings.Add(new SecretMappingOptions
                    {
                        SecretPath = "sample/demo",
                        Bindings = new()
                        {
                            ["username"] = "Sample:Username",
                            ["password"] = "Sample:Password"
                        }
                    });

                    // Token renewal
                    options.TokenRenewal.Enabled = true;
                    options.TokenRenewal.CheckIntervalSeconds = 60;
                });
            });
    */

    private static async Task RunSampleAsync(IServiceProvider services)
    {
        var configuration = services.GetRequiredService<IConfiguration>();
        var vaultEnabled = configuration.GetValue<bool>("VaultaX:Enabled");

        if (!vaultEnabled)
        {
            AnsiConsole.MarkupLine("[yellow]Warning: VaultaX is disabled in configuration.[/]");
            AnsiConsole.MarkupLine("[yellow]Enable VaultaX in appsettings.json to run this sample.[/]");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]Set VaultaX:Enabled to true and configure your Vault server.[/]");
            return;
        }

        // Sample 1: Key-Value Engine - Read secrets
        await RunKeyValueSampleAsync(services);

        AnsiConsole.WriteLine();

        // Sample 2: Transit Engine - Sign and verify data
        await RunTransitSampleAsync(services);
    }

    private static async Task RunKeyValueSampleAsync(IServiceProvider services)
    {
        try
        {
            var kvEngine = services.GetRequiredService<IKeyValueEngine>();

            await AnsiConsole.Status()
                .StartAsync("Reading secrets from Vault KV engine...", async ctx =>
                {
                    var secretPath = "sample/demo";

                    AnsiConsole.MarkupLine($"[cyan]Reading secret from path:[/] [white]{secretPath}[/]");

                    try
                    {
                        var secrets = await kvEngine.ReadAsync(secretPath);

                        if (secrets.Count > 0)
                        {
                            var table = new Table();
                            table.AddColumn("Key");
                            table.AddColumn("Value");

                            foreach (var kvp in secrets)
                            {
                                table.AddRow(
                                    $"[yellow]{kvp.Key}[/]",
                                    $"[green]{kvp.Value?.ToString() ?? "(null)"}[/]");
                            }

                            AnsiConsole.Write(table);
                        }
                        else
                        {
                            AnsiConsole.MarkupLine("[yellow]No secrets found at this path.[/]");
                        }
                    }
                    catch (VaultSecretNotFoundException)
                    {
                        AnsiConsole.MarkupLine($"[yellow]Secret not found at path: {secretPath}[/]");
                        AnsiConsole.MarkupLine("[dim]To create a test secret, run:[/]");
                        AnsiConsole.MarkupLine($"[dim]vault kv put secret/{secretPath} username=admin password=secret123 api_key=my-key[/]");
                    }
                });
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error accessing KV engine: {ex.Message}[/]");
        }
    }

    private static async Task RunTransitSampleAsync(IServiceProvider services)
    {
        try
        {
            var transitEngine = services.GetRequiredService<ITransitEngine>();

            await AnsiConsole.Status()
                .StartAsync("Signing data with Vault Transit engine...", async ctx =>
                {
                    var keyName = "sample-signing-key";
                    var documentData = "This is a sample document to be signed";
                    var dataBytes = Encoding.UTF8.GetBytes(documentData);

                    AnsiConsole.MarkupLine($"[cyan]Using Transit key:[/] [white]{keyName}[/]");
                    AnsiConsole.MarkupLine($"[cyan]Document to sign:[/] [white]{documentData}[/]");
                    AnsiConsole.WriteLine();

                    ctx.Status("Checking Transit key...");
                    var keyInfo = await transitEngine.GetKeyInfoAsync(keyName);

                    if (keyInfo == null)
                    {
                        AnsiConsole.MarkupLine($"[yellow]Transit key '{keyName}' not found.[/]");
                        AnsiConsole.MarkupLine("[dim]To create a signing key, run:[/]");
                        AnsiConsole.MarkupLine($"[dim]vault write transit/keys/{keyName} type=rsa-2048[/]");
                        return;
                    }

                    AnsiConsole.MarkupLine($"[green]✓[/] Key exists: [white]{keyInfo.Type}[/] (version {keyInfo.LatestVersion})");
                    AnsiConsole.WriteLine();

                    ctx.Status("Signing data...");
                    var signResponse = await transitEngine.SignAsync(new TransitSignRequest
                    {
                        KeyName = keyName,
                        Data = dataBytes,
                        HashAlgorithm = TransitHashAlgorithm.Sha256,
                        SignatureAlgorithm = TransitSignatureAlgorithm.Pss,
                        Prehashed = false
                    });

                    AnsiConsole.MarkupLine($"[green]✓[/] Data signed successfully!");
                    AnsiConsole.MarkupLine($"[cyan]Signature:[/] [white]{signResponse.Signature[..50]}...[/]");
                    AnsiConsole.MarkupLine($"[cyan]Key version used:[/] [white]{signResponse.KeyVersion}[/]");
                    AnsiConsole.WriteLine();

                    ctx.Status("Verifying signature...");
                    var isValid = await transitEngine.VerifyAsync(new TransitVerifyRequest
                    {
                        KeyName = keyName,
                        Data = dataBytes,
                        Signature = signResponse.Signature,
                        HashAlgorithm = TransitHashAlgorithm.Sha256,
                        SignatureAlgorithm = TransitSignatureAlgorithm.Pss,
                        Prehashed = false
                    });

                    if (isValid)
                    {
                        AnsiConsole.MarkupLine("[green]✓ Signature verification: VALID[/]");
                    }
                    else
                    {
                        AnsiConsole.MarkupLine("[red]✗ Signature verification: INVALID[/]");
                    }

                    AnsiConsole.WriteLine();

                    ctx.Status("Testing with tampered data...");
                    var tamperedData = Encoding.UTF8.GetBytes("This document has been tampered!");
                    var tamperedValid = await transitEngine.VerifyAsync(new TransitVerifyRequest
                    {
                        KeyName = keyName,
                        Data = tamperedData,
                        Signature = signResponse.Signature,
                        HashAlgorithm = TransitHashAlgorithm.Sha256,
                        SignatureAlgorithm = TransitSignatureAlgorithm.Pss,
                        Prehashed = false
                    });

                    AnsiConsole.MarkupLine($"[cyan]Tampered data verification:[/] {(tamperedValid ? "[red]VALID[/]" : "[green]INVALID (as expected)[/]")}");

                    AnsiConsole.WriteLine();
                    var panel = new Panel(
                        "[dim]The Transit engine provides cryptographic operations without exposing private keys.\n" +
                        "Private keys never leave Vault, making it ideal for secure signing operations.[/]")
                    {
                        Header = new PanelHeader("[yellow]Transit Engine Benefits[/]"),
                        Border = BoxBorder.Rounded
                    };
                    AnsiConsole.Write(panel);
                });
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error accessing Transit engine: {ex.Message}[/]");
        }
    }
}
