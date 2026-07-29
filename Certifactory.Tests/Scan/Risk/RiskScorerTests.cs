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

public class RiskScorerTests
{
    private static readonly DateTime Now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    // A vulnerable RSA root CA (key-establishment usage), valid 15 years.
    private static DiscoveredCertificate RootCaKex(string thumb) => new(
        SubjectName: "CN=root", IssuerName: "CN=root",
        NotBefore: Now, NotAfter: Now.AddYears(15),
        Sha256Thumbprint: thumb,
        SignatureAlgorithmOid: "1.2.840.113549.1.1.11", // RSA sig
        SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",  // RSA key
        SubjectKeySizeBits: 4096,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "root.pfx",
        KeyUsages: new[] { false, false, true, false, true, true, true, false, false }, // keyEnc+keyAgree+certSign+crl
        IsCertificateAuthority: true);

    // A vulnerable RSA leaf, signature-only, expiring in 6 months.
    private static DiscoveredCertificate LeafSig(string thumb) => new(
        SubjectName: "CN=leaf", IssuerName: "CN=root",
        NotBefore: Now, NotAfter: Now.AddMonths(6),
        Sha256Thumbprint: thumb,
        SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
        SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",
        SubjectKeySizeBits: 4096,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "leaf.pfx",
        KeyUsages: new[] { true, false, false, false, false, false, false, false, false }, // digitalSignature only
        IsCertificateAuthority: false);

    // A pure quantum-safe leaf.
    private static DiscoveredCertificate SafeLeaf(string thumb) => new(
        SubjectName: "CN=safe", IssuerName: "CN=root",
        NotBefore: Now, NotAfter: Now.AddYears(15),
        Sha256Thumbprint: thumb,
        SignatureAlgorithmOid: "2.16.840.1.101.3.4.3.18", // ML-DSA-65
        SubjectKeyAlgorithmOid: "2.16.840.1.101.3.4.3.18",
        SubjectKeySizeBits: null,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "safe.pfx",
        KeyUsages: new[] { true, false, false, false, false, false, false, false, false },
        IsCertificateAuthority: false);

    private static RiskAssessment ScoreOf(params DiscoveredCertificate[] certs)
    {
        var doc = CbomBuilder.Build(certs, "H", "2026-01-01T00:00:00Z", "1.0.0");
        return RiskScorer.Score(doc, new RiskOptions(), Now);
    }

    [Fact]
    public void Root_ca_key_establishment_scores_critical()
    {
        var a = ScoreOf(RootCaKex("rr")).Assets.Single();
        // exposure = 0.40*1.0 + 0.25*1.0 + 0.20*1.0 + 0.15*0.2 = 0.88 ; readiness 1.0 => 88
        a.Score.Should().BeApproximately(88.0, 0.5);
        a.Grade.Should().Be('F');
    }

    [Fact]
    public void Leaf_signature_scores_guarded()
    {
        var a = ScoreOf(LeafSig("ll")).Assets.Single();
        // exposure = 0.40*0.3 + 0.25*0.3 + 0.20*0.15 + 0.15*0.2 = 0.255 ; readiness 1.0 => 25.5
        a.Score.Should().BeApproximately(25.5, 0.5);
        a.Grade.Should().Be('B');
    }

    [Fact]
    public void Quantum_safe_asset_scores_zero()
    {
        var a = ScoreOf(SafeLeaf("ss")).Assets.Single();
        a.Score.Should().Be(0);
        a.Grade.Should().Be('A');
    }

    [Fact]
    public void Inventory_score_is_mean_and_assets_sorted_worst_first()
    {
        var assessment = ScoreOf(RootCaKex("rr"), LeafSig("ll"), SafeLeaf("ss"));
        assessment.Assets.Select(x => x.Score).Should().BeInDescendingOrder();
        assessment.InventoryScore.Should().BeApproximately((88.0 + 25.5 + 0.0) / 3.0, 0.6);
        assessment.BandCounts['F'].Should().Be(1);
        assessment.BandCounts['A'].Should().Be(1);
    }

    [Fact]
    public void Unenriched_cbom_uses_conservative_defaults_and_flags_absence()
    {
        // Build a doc, then strip the certifactory:* properties to simulate an old CBOM.
        var doc = CbomBuilder.Build(new[] { LeafSig("ll") }, "H", "2026-01-01T00:00:00Z", "1.0.0");
        foreach (var c in doc.Components) c.Properties = null;

        var assessment = RiskScorer.Score(doc, new RiskOptions(), Now);
        assessment.EnrichmentPresent.Should().BeFalse();
        var a = assessment.Assets.Single();
        // Missing usage => worst-case 1.0, missing role => leaf(0.3):
        // exposure = 0.40*1.0 + 0.25*0.3 + 0.20*0.15 + 0.15*0.2 = 0.535 => 53.5
        a.Score.Should().BeApproximately(53.5, 0.5);
    }
}
