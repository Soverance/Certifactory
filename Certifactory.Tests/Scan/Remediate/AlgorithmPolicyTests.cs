// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Certifactory.Tests.Scan.Remediate;

using Soverance.Certifactory.Scan.Remediate;
using Xunit;

public class AlgorithmPolicyTests
{
    [Theory]
    [InlineData("root-ca", "signature", 30, TargetAlgorithm.MlDsa65)]          // CA wins over long-validity
    [InlineData("intermediate-ca", "signature", 30, TargetAlgorithm.MlDsa65)]
    [InlineData("leaf", "signature", 30, TargetAlgorithm.SlhDsa256s)]          // long-lived non-CA signing
    [InlineData("leaf", "signature", 10, TargetAlgorithm.SlhDsa256s)]          // boundary: >= 10 years
    [InlineData("leaf", "signature", 9, TargetAlgorithm.Hybrid)]               // below threshold
    [InlineData("leaf", "key-establishment", 30, TargetAlgorithm.Hybrid)]      // long but not signing
    [InlineData("leaf", "signature", 3, TargetAlgorithm.Hybrid)]
    [InlineData("tls-endpoint", "key-establishment", 1, TargetAlgorithm.Hybrid)]
    public void Recommend_FollowsPrecedence(string role, string usage, double years, TargetAlgorithm expected)
        => Assert.Equal(expected, AlgorithmPolicy.Recommend(role, usage, years));

    [Theory]
    [InlineData("root-ca", "ca")]
    [InlineData("intermediate-ca", "ca")]
    [InlineData("leaf", "server")]
    [InlineData("tls-endpoint", "server")]
    public void CommandName_ByRole(string role, string expected)
        => Assert.Equal(expected, AlgorithmPolicy.CommandName(role));
}
