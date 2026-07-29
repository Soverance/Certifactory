// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Linq;
using FluentAssertions;
using Org.BouncyCastle.Security;
using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Tls;
using Xunit;

namespace Certifactory.Tests.Scan;

public class CbomGraphTests
{
    private static DiscoveredCertificate Cert(string thumb, string sigOid, string keyOid) => new(
        SubjectName: "CN=x", IssuerName: "CN=x",
        NotBefore: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        NotAfter: new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        Sha256Thumbprint: thumb, SignatureAlgorithmOid: sigOid,
        SubjectKeyAlgorithmOid: keyOid, SubjectKeySizeBits: 4096,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "s");

    // TlsCbomBuilder.Build only emits a protocol component for endpoints with a
    // non-empty served chain (Succeeded && Chain.Count > 0); a real leaf cert is
    // needed here so the KexFor test below has a protocol component to resolve.
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
    public void AlgorithmsFor_resolves_signature_and_subject_key_algorithms()
    {
        // RSA sig + EC key
        var doc = CbomBuilder.Build(new[]
        {
            Cert("aa", "1.2.840.113549.1.1.11", "1.2.840.10045.2.1")
        }, "H", "2026-07-27T00:00:00Z", "1.0.0");

        var graph = new CbomGraph(doc);
        var oids = graph.AlgorithmsFor("cert:aa").Select(a => a.Oid).ToList();

        oids.Should().Contain("1.2.840.113549.1.1.11"); // signature alg (direct dep)
        oids.Should().Contain("1.2.840.10045.2.1");      // subject key alg (via key hop)
    }

    [Fact]
    public void DependsOn_returns_empty_for_unknown_ref_and_survives_duplicate_refs()
    {
        var doc = new CbomDocument
        {
            Dependencies =
            {
                new Dependency { Ref = "dup", DependsOn = { "a" } },
                new Dependency { Ref = "dup", DependsOn = { "b" } }, // duplicate ref
            }
        };
        var graph = new CbomGraph(doc);

        graph.DependsOn("missing").Should().BeEmpty();
        graph.DependsOn("dup").Should().Equal("a"); // first-seen wins, no throw
    }

    [Fact]
    public void KexFor_classifies_tls_protocol_component_by_group()
    {
        var endpoint = new TlsEndpointResult(
            "h", 443, Succeeded: true, TlsVersion: "1.3", CipherSuite: "TLS_AES_256_GCM_SHA384",
            KexGroup: "X25519MLKEM768", Chain: new[] { Leaf("h") },
            FailureReason: null);
        var doc = TlsCbomBuilder.Build(new[] { endpoint }, "H", "2026-07-28T00:00:00Z", "1.0.0");
        var graph = new CbomGraph(doc);

        var protocol = doc.Components.Single(c => c.CryptoProperties?.AssetType == "protocol");
        var kex = graph.KexFor(protocol.BomRef);
        kex.IsHybrid.Should().BeTrue();
    }
}
