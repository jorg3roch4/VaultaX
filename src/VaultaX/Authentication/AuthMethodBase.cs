using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Configuration;
using VaultSharp.V1.AuthMethods;

namespace VaultaX.Authentication;

/// <summary>
/// Base class for authentication methods.
/// </summary>
public abstract class AuthMethodBase : Abstractions.IAuthMethod
{
    /// <summary>
    /// The authentication options.
    /// </summary>
    protected AuthenticationOptions Options { get; }

    /// <summary>
    /// Creates a new auth method with the specified options.
    /// </summary>
    protected AuthMethodBase(AuthenticationOptions options)
    {
        Options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    public abstract string MethodName { get; }

    /// <inheritdoc />
    public abstract Task<Abstractions.AuthResult> AuthenticateAsync(CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public abstract IAuthMethodInfo GetAuthMethodInfo();

    /// <summary>
    /// Gets the mount path for this auth method, using the default if not specified.
    /// </summary>
    protected string GetMountPath(string defaultPath)
    {
        return string.IsNullOrWhiteSpace(Options.MountPath) ? defaultPath : Options.MountPath;
    }

    /// <summary>
    /// Gets an environment variable value, throwing if not found.
    /// Supports "static:" prefix for direct values and "env:" prefix for explicit env vars.
    /// </summary>
    protected static string GetRequiredEnvVar(string? envVarName, string description)
    {
        if (string.IsNullOrWhiteSpace(envVarName))
        {
            throw new Exceptions.VaultaXConfigurationException(
                $"Environment variable name for {description} is not configured.");
        }

        var value = ResolveValue(envVarName);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new Exceptions.VaultaXConfigurationException(
                $"Environment variable '{envVarName}' for {description} is not set or is empty.");
        }

        return value;
    }

    /// <summary>
    /// Gets an optional environment variable value.
    /// Supports "static:" prefix for direct values and "env:" prefix for explicit env vars.
    /// </summary>
    protected static string? GetOptionalEnvVar(string? envVarName)
    {
        if (string.IsNullOrWhiteSpace(envVarName))
        {
            return null;
        }

        return ResolveValue(envVarName);
    }

    /// <summary>
    /// Resolves a value that can be either a static value, an explicit env var, or a default env var.
    /// </summary>
    private static string? ResolveValue(string name)
    {
        // Support static values with "static:" prefix (for development/testing only)
        if (name.StartsWith("static:", StringComparison.OrdinalIgnoreCase))
            return name[7..];

        // Support explicit env var prefix "env:"
        if (name.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
            return Environment.GetEnvironmentVariable(name[4..]);

        // Default: treat as environment variable name
        return Environment.GetEnvironmentVariable(name);
    }
}
