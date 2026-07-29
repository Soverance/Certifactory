// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Certifactory.Tests.Scan.Remediate;

using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Remediate;
using Soverance.Certifactory.Scan.Risk;
using Xunit;

public class RemediationPlannerTests
{
    private static readonly DateTime Now = new(2026, 7, 29, 0, 0, 0, DateTimeKind.Utc);

    // RSA (vulnerable) unless overridden. ku = KeyUsage bit array.
    private static DiscoveredCertificate Rsa(
        string cn, bool ca, bool hasKey, int validYears, bool[]? ku, string thumb) => new(
            SubjectName: cn, IssuerName: cn,
            NotBefore: Now, NotAfter: Now.AddYears(validYears),
            Sha256Thumbprint: thumb,
            SignatureAlgorithmOid: "1.2.840.113549.1.1.11",   // sha256WithRSA (vulnerable)
            SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",   // rsaEncryption (vulnerable)
            SubjectKeySizeBits: 2048, IsHybrid: false,
            AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
            SourceDescription: "t", KeyUsages: ku, IsCertificateAuthority: ca, HasPrivateKey: hasKey);

    // KeyUsage bit arrays (BouncyCastle order). Signing CA: keyCertSign(5). Leaf sig: digitalSignature(0).
    private static bool[] CaSign() { var b = new bool[9]; b[5] = true; return b; }
    private static bool[] LeafSign() { var b = new bool[9]; b[0] = true; return b; }
    private static bool[] LeafKeyEst() { var b = new bool[9]; b[2] = true; return b; }

    private static RemediationPlan Plan(params DiscoveredCertificate[] certs)
    {
        var doc = CbomBuilder.Build(certs, "host", "2026-07-29T00:00:00Z", "0.0.0");
        return RemediationPlanner.Plan(doc, new RiskOptions(), Now);
    }

    [Fact]
    public void OwnedVulnerableCa_ReissuesMlDsa()
    {
        var plan = Plan(Rsa("CN=MyCA", ca: true, hasKey: true, validYears: 30, ku: CaSign(), thumb: "ca1"));
        var item = plan.All.Single();
        Assert.Equal(RemediationAction.ReissuePqc, item.Action);
        Assert.Equal(TargetAlgorithm.MlDsa65, item.Target);
        Assert.Contains("--algorithm ml-dsa-65", item.CommandHint);
        Assert.Contains("certifactory ca", item.CommandHint);
        Assert.Equal(1, plan.ControllableCount);
        // CN extraction: the hint uses the bare CN, not the raw "CN=MyCA" subject DN.
        Assert.Contains("\"MyCA\"", item.CommandHint);
        Assert.DoesNotContain("CN=MyCA", item.CommandHint);
    }

    [Fact]
    public void OwnedLongLivedSigningLeaf_ReissuesSlhDsa()
    {
        var plan = Plan(Rsa("CN=CodeSign", ca: false, hasKey: true, validYears: 15, ku: LeafSign(), thumb: "cs1"));
        var item = plan.All.Single();
        Assert.Equal(TargetAlgorithm.SlhDsa256s, item.Target);
        Assert.Contains("certifactory server", item.CommandHint);
        // server's real signature is 6 positionals; the hint must be runnable, not
        // the 3-positional "ca" shape reused by mistake.
        Assert.Contains("<server-ip>", item.CommandHint);
    }

    [Fact]
    public void OwnedTlsLeaf_ReissuesHybrid()
    {
        var plan = Plan(Rsa("CN=web", ca: false, hasKey: true, validYears: 1, ku: LeafKeyEst(), thumb: "w1"));
        Assert.Equal(TargetAlgorithm.Hybrid, plan.All.Single().Target);
    }

    [Fact]
    public void PublicOnlyVulnerableRoot_IsVendorDependent()
    {
        var plan = Plan(Rsa("CN=DigiCert", ca: true, hasKey: false, validYears: 20, ku: CaSign(), thumb: "d1"));
        Assert.Equal(RemediationAction.MonitorVendor, plan.All.Single().Action);
        Assert.Equal(1, plan.VendorDependentCount);
        Assert.Empty(plan.Controllable);
    }

    [Fact]
    public void UnenrichedCbom_FallsBackToManualReview()
    {
        // Strip properties to simulate a third-party / older CBOM.
        var doc = CbomBuilder.Build(
            new[] { Rsa("CN=x", ca: false, hasKey: true, validYears: 5, ku: LeafSign(), thumb: "x1") },
            "host", "2026-07-29T00:00:00Z", "0.0.0");
        foreach (var c in doc.Components) c.Properties = null;

        var plan = RemediationPlanner.Plan(doc, new RiskOptions(), Now);
        Assert.False(plan.CustodyPresent);
        Assert.Equal(RemediationAction.ManualReview, plan.All.Single(a => a.BomRef == "cert:x1").Action);
    }

    [Fact]
    public void Controllable_IsSortedWorstFirst()
    {
        var plan = Plan(
            Rsa("CN=low",  ca: false, hasKey: true, validYears: 1,  ku: LeafSign(), thumb: "lo"),
            Rsa("CN=high", ca: true,  hasKey: true, validYears: 30, ku: CaSign(),  thumb: "hi"));
        Assert.Equal("CN=high", plan.Controllable.First().Name);
    }

    // --- Characterization tests: pin PlanOne's readiness-factor -> action mapping
    // (rf <= 0.0 -> None; 0 < rf < 0.85 -> AlreadyHybrid; rf >= 0.85 -> actionable).
    // These exercise the REAL RemediationPlanner.Plan via CbomBuilder.Build, never
    // RiskScorer/RiskModel directly, so a future change to the scorer's readiness
    // constants would fail here instead of silently rerouting assets.

    // ML-DSA-65 (FIPS 204) — recognized PqReadiness.QuantumSafe OID, see Scan/QuantumClassifier.cs.
    private const string MlDsa65Oid = "2.16.840.1.101.3.4.3.18";

    // Unrecognized by QuantumClassifier -> classifies as PqReadiness.NotApplicable
    // ("unknown"), which RiskScorer maps to RiskReadiness.Unknown (rf 0.85).
    private const string BogusOid = "1.2.3.4.5.6.7.8";

    [Fact]
    public void QuantumSafeCert_ReadinessFactorZero_IsNone()
    {
        // Both signature and subject-key OIDs are quantum-safe -> the cert's whole
        // algorithm set is QuantumSafe -> rf = 0.0 -> Action.None.
        var cert = new DiscoveredCertificate(
            SubjectName: "CN=pqc-leaf", IssuerName: "CN=pqc-leaf",
            NotBefore: Now, NotAfter: Now.AddYears(3),
            Sha256Thumbprint: "qs1",
            SignatureAlgorithmOid: MlDsa65Oid,
            SubjectKeyAlgorithmOid: MlDsa65Oid,
            SubjectKeySizeBits: null, IsHybrid: false,
            AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
            SourceDescription: "t", KeyUsages: LeafSign(),
            IsCertificateAuthority: false, HasPrivateKey: true);

        var plan = Plan(cert);
        Assert.Equal(RemediationAction.None, plan.All.Single().Action);
    }

    [Fact]
    public void HybridCert_ReadinessFactorPointThreeFive_IsAlreadyHybrid()
    {
        // Vulnerable RSA primary (same OIDs the Rsa() helper uses) plus a quantum-safe
        // ML-DSA-65 alt-signature -> algorithm set contains both Vulnerable and
        // QuantumSafe -> RiskReadiness.Hybrid -> rf = 0.35 -> Action.AlreadyHybrid.
        var cert = Rsa("CN=hybrid-leaf", ca: false, hasKey: true, validYears: 3, ku: LeafSign(), thumb: "hy1")
            with { IsHybrid = true, AltSignatureAlgorithmOid = MlDsa65Oid };

        var plan = Plan(cert);
        Assert.Equal(RemediationAction.AlreadyHybrid, plan.All.Single().Action);
    }

    [Fact]
    public void UnknownAlgorithmCert_ReadinessFactorPointEightFive_IsActionable()
    {
        // Bogus OID -> RiskReadiness.Unknown -> rf = 0.85, which must still be
        // treated as actionable (the `rf < 0.85` branch excludes it), not silently
        // fall into AlreadyHybrid/None. Owned-key -> routes through to ReissuePqc.
        var cert = new DiscoveredCertificate(
            SubjectName: "CN=unknown-alg", IssuerName: "CN=unknown-alg",
            NotBefore: Now, NotAfter: Now.AddYears(3),
            Sha256Thumbprint: "unk1",
            SignatureAlgorithmOid: BogusOid,
            SubjectKeyAlgorithmOid: BogusOid,
            SubjectKeySizeBits: 2048, IsHybrid: false,
            AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
            SourceDescription: "t", KeyUsages: LeafSign(),
            IsCertificateAuthority: false, HasPrivateKey: true);

        var plan = Plan(cert);
        Assert.Equal(RemediationAction.ReissuePqc, plan.All.Single().Action);
    }
}
