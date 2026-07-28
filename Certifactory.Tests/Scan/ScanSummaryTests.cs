// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using FluentAssertions;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan;

public class ScanSummaryTests
{
    private static DiscoveredCertificate Cert(string thumb, string sigOid, bool hybrid = false, string? altSig = null)
        => new(
            SubjectName: "CN=x", IssuerName: "CN=x",
            NotBefore: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter: new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Sha256Thumbprint: thumb, SignatureAlgorithmOid: sigOid,
            SubjectKeyAlgorithmOid: sigOid, SubjectKeySizeBits: null,
            IsHybrid: hybrid, AltSignatureAlgorithmOid: altSig, AltKeyAlgorithmOid: altSig,
            SourceDescription: "s");

    [Fact]
    public void Counts_vulnerable_transitional_and_safe()
    {
        var doc = CbomBuilder.Build(new[]
        {
            Cert("a", "1.2.840.113549.1.1.11"),                                   // RSA -> vulnerable
            Cert("b", "2.16.840.1.101.3.4.3.18"),                                 // ML-DSA -> safe
            Cert("c", "1.2.840.113549.1.1.11", hybrid: true, altSig: "2.16.840.1.101.3.4.3.18"), // hybrid -> transitional
        }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");

        var counts = ScanSummary.Compute(doc);
        counts.Vulnerable.Should().Be(1);
        counts.QuantumSafe.Should().Be(1);
        counts.Transitional.Should().Be(1);
        counts.CertificateCount.Should().Be(3);
        counts.KeyCount.Should().Be(3);
        counts.AlgorithmCount.Should().Be(2);  // Verify actual value
    }

    [Fact]
    public void Cert_with_safe_signature_but_vulnerable_key_is_not_counted_quantum_safe()
    {
        var mixed = new DiscoveredCertificate(
            SubjectName: "CN=mixed", IssuerName: "CN=mixed",
            NotBefore: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter: new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Sha256Thumbprint: "mixed",
            SignatureAlgorithmOid: "2.16.840.1.101.3.4.3.18", // ML-DSA-65 (safe)
            SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",   // RSA (vulnerable)
            SubjectKeySizeBits: 4096,
            IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
            SourceDescription: "s");

        var doc = CbomBuilder.Build(new[] { mixed }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");
        var counts = ScanSummary.Compute(doc);

        counts.QuantumSafe.Should().Be(0);
        counts.Transitional.Should().Be(1); // safe sig + vulnerable key = mixed = transitional
    }

    [Fact]
    public void Render_contains_all_three_buckets()
    {
        var counts = new PqReadinessCounts(41, 3, 3, 47, 31, 6);
        var text = ScanSummary.Render(counts);
        text.Should().Contain("quantum-vulnerable");
        text.Should().Contain("hybrid");
        text.Should().Contain("quantum-safe");
        text.Should().Contain("41");
    }
}
