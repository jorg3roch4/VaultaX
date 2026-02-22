using System;
using System.Collections.Generic;
using Microsoft.Extensions.Options;
using Moq;
using VaultaX.Abstractions;
using VaultaX.Configuration;

namespace VaultaX.Tests.Helpers;

public static class VaultMockHelper
{
    public static (Mock<IVaultClient> VaultaXClient, Mock<VaultSharp.IVaultClient> VaultSharpClient) CreateMockVaultClient()
    {
        var mockVaultaXClient = new Mock<IVaultClient>();
        var mockVaultSharpClient = new Mock<VaultSharp.IVaultClient>();

        mockVaultaXClient
            .Setup(c => c.GetUnderlyingClient())
            .Returns(mockVaultSharpClient.Object);

        return (mockVaultaXClient, mockVaultSharpClient);
    }

    public static IOptions<VaultaXOptions> CreateOptions(Action<VaultaXOptions>? configure = null)
    {
        var options = new VaultaXOptions
        {
            Enabled = true,
            Address = "http://localhost:8200",
            MountPoint = "secret",
            KvVersion = 2,
            Authentication = new AuthenticationOptions
            {
                Method = "Token",
                Token = "static:test-token"
            },
            Mappings =
            [
                new SecretMappingOptions
                {
                    SecretPath = "test",
                    Bindings = new Dictionary<string, string> { { "key", "value" } }
                }
            ]
        };

        configure?.Invoke(options);

        return Options.Create(options);
    }

    public static IOptions<VaultaXOptions> CreateDefaultOptions() => CreateOptions();
}
