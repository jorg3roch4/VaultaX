using System;

namespace VaultaX.Exceptions;

/// <summary>
/// Base exception for all VaultaX errors.
/// </summary>
public class VaultaXException : Exception
{
    /// <summary>
    /// Creates a new VaultaX exception.
    /// </summary>
    public VaultaXException()
    {
    }

    /// <summary>
    /// Creates a new VaultaX exception with a message.
    /// </summary>
    public VaultaXException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new VaultaX exception with a message and inner exception.
    /// </summary>
    public VaultaXException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when VaultaX configuration is invalid.
/// </summary>
public class VaultaXConfigurationException : VaultaXException
{
    /// <summary>
    /// The configuration key that is invalid or missing.
    /// </summary>
    public string? ConfigurationKey { get; }

    /// <summary>
    /// Creates a new configuration exception.
    /// </summary>
    public VaultaXConfigurationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new configuration exception with a configuration key.
    /// </summary>
    public VaultaXConfigurationException(string message, string configurationKey) : base(message)
    {
        ConfigurationKey = configurationKey;
    }

    /// <summary>
    /// Creates a new configuration exception with an inner exception.
    /// </summary>
    public VaultaXConfigurationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when authentication with Vault fails.
/// </summary>
public class VaultAuthenticationException : VaultaXException
{
    /// <summary>
    /// The authentication method that failed.
    /// </summary>
    public string? AuthMethod { get; }

    /// <summary>
    /// Creates a new authentication exception.
    /// </summary>
    public VaultAuthenticationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new authentication exception with the auth method.
    /// </summary>
    public VaultAuthenticationException(string message, string authMethod) : base(message)
    {
        AuthMethod = authMethod;
    }

    /// <summary>
    /// Creates a new authentication exception with an inner exception.
    /// </summary>
    public VaultAuthenticationException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Creates a new authentication exception with the auth method and inner exception.
    /// </summary>
    public VaultAuthenticationException(string message, string authMethod, Exception innerException)
        : base(message, innerException)
    {
        AuthMethod = authMethod;
    }
}

/// <summary>
/// Exception thrown when a connection to Vault cannot be established.
/// </summary>
public class VaultConnectionException : VaultaXException
{
    /// <summary>
    /// The Vault address that could not be reached.
    /// </summary>
    public string? VaultAddress { get; }

    /// <summary>
    /// Creates a new connection exception.
    /// </summary>
    public VaultConnectionException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new connection exception with the Vault address.
    /// </summary>
    public VaultConnectionException(string message, string vaultAddress) : base(message)
    {
        VaultAddress = vaultAddress;
    }

    /// <summary>
    /// Creates a new connection exception with an inner exception.
    /// </summary>
    public VaultConnectionException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Creates a new connection exception with the Vault address and inner exception.
    /// </summary>
    public VaultConnectionException(string message, string vaultAddress, Exception innerException)
        : base(message, innerException)
    {
        VaultAddress = vaultAddress;
    }
}

/// <summary>
/// Exception thrown when a secret is not found in Vault.
/// </summary>
public class VaultSecretNotFoundException : VaultaXException
{
    /// <summary>
    /// The path to the secret that was not found.
    /// </summary>
    public string SecretPath { get; }

    /// <summary>
    /// Creates a new secret not found exception.
    /// </summary>
    public VaultSecretNotFoundException(string secretPath)
        : base($"Secret not found at path: {secretPath}")
    {
        SecretPath = secretPath;
    }

    /// <summary>
    /// Creates a new secret not found exception with a custom message.
    /// </summary>
    public VaultSecretNotFoundException(string message, string secretPath) : base(message)
    {
        SecretPath = secretPath;
    }

    /// <summary>
    /// Creates a new secret not found exception with an inner exception.
    /// </summary>
    public VaultSecretNotFoundException(string secretPath, Exception innerException)
        : base($"Secret not found at path: {secretPath}", innerException)
    {
        SecretPath = secretPath;
    }
}

/// <summary>
/// Exception thrown when token renewal fails.
/// </summary>
public class VaultTokenRenewalException : VaultaXException
{
    /// <summary>
    /// The number of consecutive renewal failures.
    /// </summary>
    public int ConsecutiveFailures { get; }

    /// <summary>
    /// Creates a new token renewal exception.
    /// </summary>
    public VaultTokenRenewalException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new token renewal exception with failure count.
    /// </summary>
    public VaultTokenRenewalException(string message, int consecutiveFailures) : base(message)
    {
        ConsecutiveFailures = consecutiveFailures;
    }

    /// <summary>
    /// Creates a new token renewal exception with an inner exception.
    /// </summary>
    public VaultTokenRenewalException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Creates a new token renewal exception with failure count and inner exception.
    /// </summary>
    public VaultTokenRenewalException(string message, int consecutiveFailures, Exception innerException)
        : base(message, innerException)
    {
        ConsecutiveFailures = consecutiveFailures;
    }
}

/// <summary>
/// Exception thrown when a Transit engine operation fails.
/// </summary>
public class VaultTransitException : VaultaXException
{
    /// <summary>
    /// The operation that failed.
    /// </summary>
    public string? Operation { get; }

    /// <summary>
    /// The key name involved in the operation.
    /// </summary>
    public string? KeyName { get; }

    /// <summary>
    /// Creates a new Transit exception.
    /// </summary>
    public VaultTransitException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new Transit exception with operation details.
    /// </summary>
    public VaultTransitException(string message, string operation, string? keyName = null) : base(message)
    {
        Operation = operation;
        KeyName = keyName;
    }

    /// <summary>
    /// Creates a new Transit exception with an inner exception.
    /// </summary>
    public VaultTransitException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Creates a new Transit exception with operation details and inner exception.
    /// </summary>
    public VaultTransitException(string message, string operation, string? keyName, Exception innerException)
        : base(message, innerException)
    {
        Operation = operation;
        KeyName = keyName;
    }
}

/// <summary>
/// Exception thrown when a PKI engine operation fails.
/// </summary>
public class VaultPkiException : VaultaXException
{
    /// <summary>
    /// The operation that failed.
    /// </summary>
    public string? Operation { get; }

    /// <summary>
    /// Creates a new PKI exception.
    /// </summary>
    public VaultPkiException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new PKI exception with operation details.
    /// </summary>
    public VaultPkiException(string message, string operation) : base(message)
    {
        Operation = operation;
    }

    /// <summary>
    /// Creates a new PKI exception with an inner exception.
    /// </summary>
    public VaultPkiException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Creates a new PKI exception with operation details and inner exception.
    /// </summary>
    public VaultPkiException(string message, string operation, Exception innerException)
        : base(message, innerException)
    {
        Operation = operation;
    }
}
