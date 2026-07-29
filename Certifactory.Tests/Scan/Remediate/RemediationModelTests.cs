// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Certifactory.Tests.Scan.Remediate;

using Soverance.Certifactory.Scan.Remediate;
using Xunit;

public class RemediationModelTests
{
    [Theory]
    [InlineData(TargetAlgorithm.MlDsa65, "ml-dsa-65")]
    [InlineData(TargetAlgorithm.SlhDsa256s, "slh-dsa-256s")]
    [InlineData(TargetAlgorithm.Hybrid, "hybrid")]
    [InlineData(TargetAlgorithm.None, "")]
    public void ToAlgorithmId_MapsToKnownAlgorithms(TargetAlgorithm t, string expected)
        => Assert.Equal(expected, t.ToAlgorithmId());
}
