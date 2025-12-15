using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Spectre.Console;
using VaultaX.Abstractions;
using VaultaX.Exceptions;
using VaultaX.Extensions;

namespace VaultaX.Sample.Console;

/// <summary>
/// Sample console application demonstrating VaultaX usage for:
/// 1. Reading secrets from Key-Value engine
/// 2. Signing data with Transit engine (private key never leaves Vault)
/// 3. Verifying signatures
/// </summary>
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

            // Build the host with VaultaX configuration
            var host = CreateHostBuilder(args).Build();

            // Run the sample
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
                // Register VaultaX services
                // This will use configuration from appsettings.json
                services.AddVaultaX(context.Configuration);
            });

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
                        // Read secret from Vault
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

                    // Check if key exists
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

                    // Sign the data
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

                    // Verify the signature
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

                    // Test with tampered data
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

                    // Additional Transit operations
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
