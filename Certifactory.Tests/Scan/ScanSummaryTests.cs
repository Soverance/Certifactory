// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using FluentAssertions;
using Org.BouncyCastle.Security;
using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Tls;
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

    private static Org.BouncyCastle.X509.X509Certificate Leaf(string cn)
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.Server, cn, "Pass", signer,
            ServerIp: "10.0.0.1", EmailAddress: null, Issuer: null));
        return DotNetUtilities.FromX509Certificate(cert);
    }

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

    [Fact]
    public void Summary_counts_tls_endpoints_by_kex_readiness()
    {
        var vuln = new TlsEndpointResult(
            "a", 443, Succeeded: true, TlsVersion: "1.3", CipherSuite: "TLS_AES_128_GCM_SHA256",
            KexGroup: "x25519", Chain: new[] { Leaf("a") }, FailureReason: null);
        var hybrid = new TlsEndpointResult(
            "b", 443, Succeeded: true, TlsVersion: "1.3", CipherSuite: "TLS_AES_256_GCM_SHA384",
            KexGroup: "X25519MLKEM768", Chain: new[] { Leaf("b") }, FailureReason: null);
        var pureSafe = new TlsEndpointResult(
            "c", 443, Succeeded: true, TlsVersion: "1.3", CipherSuite: "TLS_AES_256_GCM_SHA384",
            KexGroup: "mlkem768", Chain: new[] { Leaf("c") }, FailureReason: null);

        var doc = TlsCbomBuilder.Build(new[] { vuln, hybrid, pureSafe }, "H", "2026-07-28T00:00:00Z", "1.0.0");
        var counts = ScanSummary.Compute(doc);

        counts.TlsEndpointCount.Should().Be(3);
        counts.TlsVulnerableKex.Should().Be(1);
        counts.TlsHybridKex.Should().Be(1);
        counts.TlsSafeKex.Should().Be(1);

        // Existing file/store buckets are untouched by TLS-only endpoints
        // (the leaf certs themselves are RSA -> vulnerable, not counted here).
        var text = ScanSummary.Render(counts);
        text.Should().Contain("TLS endpoints");
        text.Should().Contain("3"); // endpoint count
    }

    [Fact]
    public void Render_omits_tls_block_when_no_protocol_components()
    {
        var doc = CbomBuilder.Build(new[]
        {
            Cert("a", "1.2.840.113549.1.1.11"),
        }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");

        var counts = ScanSummary.Compute(doc);
        counts.TlsEndpointCount.Should().Be(0);
        counts.TlsVulnerableKex.Should().Be(0);
        counts.TlsHybridKex.Should().Be(0);
        counts.TlsSafeKex.Should().Be(0);

        var text = ScanSummary.Render(counts);
        text.Should().NotContain("TLS endpoints");
    }

    [Fact]
    public void Render_includes_tls_block_with_bucketed_counts_when_endpoints_present()
    {
        var counts = new PqReadinessCounts(
            Vulnerable: 0, Transitional: 0, QuantumSafe: 0,
            CertificateCount: 0, KeyCount: 0, AlgorithmCount: 0,
            TlsEndpointCount: 21, TlsVulnerableKex: 5, TlsHybridKex: 7, TlsSafeKex: 9);

        var text = ScanSummary.Render(counts);
        text.Should().Contain("TLS endpoints");
        text.Should().Contain("21");
        text.Should().Contain("5");
        text.Should().Contain("7");
        text.Should().Contain("9");
    }
}
