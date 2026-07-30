// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Linq;
using FluentAssertions;
using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Risk;
using Xunit;

namespace Certifactory.Tests.Scan.Risk;

public class RiskScorerMoscaTests
{
    private static readonly DateTime Now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    // Vulnerable RSA leaf, signature-only, expiring in 6 months (intrinsic validity = 0.15).
    private static DiscoveredCertificate ShortLivedLeaf(string thumb) => new(
        SubjectName: "CN=leaf", IssuerName: "CN=root",
        NotBefore: Now, NotAfter: Now.AddMonths(6),
        Sha256Thumbprint: thumb,
        SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
        SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",
        SubjectKeySizeBits: 4096,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "leaf.pfx",
        KeyUsages: new[] { true, false, false, false, false, false, false, false, false },
        IsCertificateAuthority: false);

    private static AssetRisk ScoreWith(RiskOptions options)
    {
        var doc = CbomBuilder.Build(new[] { ShortLivedLeaf("ll") }, "H", "2026-01-01T00:00:00Z", "1.0.0");
        return RiskScorer.Score(doc, options, Now).Assets.Single();
    }

    [Fact]
    public void Mosca_saturates_validity_when_data_outlives_qday()
    {
        // Data must stay secret 20 years; Q-day ~2032 (~6 yrs out) => horizon crosses => validity 1.0.
        var a = ScoreWith(new RiskOptions(QuantumYear: 2032, DataShelfLife: 20, MigrationYears: 1));
        a.Factors.Validity.Should().Be(1.0);
        // exposure = 0.40*0.3 + 0.25*0.3 + 0.20*1.0 + 0.15*0.2 = 0.425 => 42.5
        a.Score.Should().BeApproximately(42.5, 0.5);
    }

    [Fact]
    public void Mosca_scales_validity_below_one_when_data_expires_before_qday()
    {
        // Short shelf life (2 yr) + migration (1 yr) = 3 yr horizon vs ~24 yrs to Q-day(2050) => 3/24 = 0.125 -> clamp 0.15.
        var a = ScoreWith(new RiskOptions(QuantumYear: 2050, DataShelfLife: 2, MigrationYears: 1));
        a.Factors.Validity.Should().BeApproximately(0.15, 0.01);
    }

    [Fact]
    public void No_mosca_flags_uses_intrinsic_validity()
    {
        var a = ScoreWith(new RiskOptions()); // no Mosca
        a.Factors.Validity.Should().Be(0.15); // 6-month cert
    }
}
