using System;
using System.Threading;
using System.Threading.Tasks;
using VaultaX.Abstractions;
using VaultaX.Configuration;
using VaultaX.Exceptions;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.AWS;

namespace VaultaX.Authentication;

/// <summary>
/// AWS authentication method for workloads running on AWS.
/// Supports both IAM and EC2 authentication types.
/// </summary>
public sealed class AwsAuthMethod : AuthMethodBase
{
    /// <inheritdoc />
    public override string MethodName => "AWS";

    /// <summary>
    /// Creates a new AWS authentication method.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    public AwsAuthMethod(AuthenticationOptions options) : base(options)
    {
    }

    /// <inheritdoc />
    public override Task<AuthResult> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new AuthResult
        {
            Token = string.Empty,
            LeaseDuration = TimeSpan.Zero,
            Renewable = true
        });
    }

    /// <inheritdoc />
    public override IAuthMethodInfo GetAuthMethodInfo()
    {
        if (string.IsNullOrWhiteSpace(Options.Role))
        {
            throw new VaultaXConfigurationException(
                "Role is required for AWS authentication.",
                "VaultaX:Authentication:Role");
        }

        var mountPath = GetMountPath("aws");
        var authType = Options.AuthType?.ToLowerInvariant() ?? "iam";

        return authType switch
        {
            "iam" => new IAMAWSAuthMethodInfo(
                mountPoint: mountPath,
                requestHeaders: GetRequiredEnvVar("AWS_IAM_REQUEST_HEADERS", "AWS IAM Request Headers"),
                roleName: Options.Role),

            "ec2" => new EC2AWSAuthMethodInfo(
                mountPoint: mountPath,
                pkcs7: GetRequiredEnvVar("AWS_EC2_PKCS7", "AWS EC2 PKCS7"),
                identity: GetRequiredEnvVar("AWS_EC2_IDENTITY", "AWS EC2 Identity"),
                signature: GetRequiredEnvVar("AWS_EC2_SIGNATURE", "AWS EC2 Signature"),
                roleName: Options.Role),

            _ => throw new VaultaXConfigurationException(
                $"Unknown AWS auth type: {authType}. Supported types are 'iam' and 'ec2'.",
                "VaultaX:Authentication:AuthType")
        };
    }
}
