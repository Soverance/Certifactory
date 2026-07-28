// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using FluentAssertions;
using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Tls;
using Xunit;

namespace Certifactory.Tests.Scan.Tls;

public class KexClassifierTests
{
    [Theory]
    [InlineData("x25519", PqReadiness.Vulnerable, false, 0)]
    [InlineData("secp256r1", PqReadiness.Vulnerable, false, 0)]
    [InlineData("X25519MLKEM768", PqReadiness.QuantumSafe, true, 3)] // hybrid classical+PQ
    [InlineData("x25519kyber768", PqReadiness.QuantumSafe, true, 3)] // hybrid classical+PQ
    [InlineData("mlkem768", PqReadiness.QuantumSafe, false, 3)] // pure PQ
    [InlineData("secp384r1mlkem1024", PqReadiness.QuantumSafe, true, 5)] // hybrid classical+PQ, NIST level 5
    [InlineData("mlkem1024", PqReadiness.QuantumSafe, false, 5)] // pure PQ, NIST level 5
    [InlineData("ffdhe4096", PqReadiness.Vulnerable, false, 0)] // classical FFDHE
    public void Classifies_known_groups(string group, PqReadiness expectedReadiness, bool expectedIsHybrid, int nist)
    {
        var c = KexClassifier.Classify(group);
        c.Readiness.Should().Be(expectedReadiness);
        c.IsHybrid.Should().Be(expectedIsHybrid);
        c.NistQuantumSecurityLevel.Should().Be(nist);
    }

    [Fact]
    public void Unknown_group_is_not_applicable_and_never_throws()
    {
        var c = KexClassifier.Classify("some-future-group");
        c.Readiness.Should().Be(PqReadiness.NotApplicable);
        c.DisplayName.Should().Contain("some-future-group");
        c.IsHybrid.Should().Be(false);
        c.NistQuantumSecurityLevel.Should().Be(0);
    }
}
