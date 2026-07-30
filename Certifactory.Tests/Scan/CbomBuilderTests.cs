// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Linq;
using FluentAssertions;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan;

public class CbomBuilderTests
{
    private static DiscoveredCertificate Rsa(string thumb) => new(
        SubjectName: "CN=rsa.example.com", IssuerName: "CN=root",
        NotBefore: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        NotAfter: new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        Sha256Thumbprint: thumb,
        SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
        SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",
        SubjectKeySizeBits: 4096,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "a.pem");

    private static DiscoveredCertificate Hybrid(string thumb) => Rsa(thumb) with
    {
        IsHybrid = true,
        AltSignatureAlgorithmOid = "2.16.840.1.101.3.4.3.18", // ML-DSA-65
        AltKeyAlgorithmOid = "2.16.840.1.101.3.4.3.18"
    };

    private static DiscoveredCertificate Ecdsa(string thumb) => Rsa(thumb) with
    {
        SignatureAlgorithmOid = "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
        SubjectKeyAlgorithmOid = "1.2.840.10045.2.1",  // id-ecPublicKey
        SubjectKeySizeBits = null
    };

    [Fact]
    public void Builds_cert_algorithm_and_key_components_wired_by_ref()
    {
        var doc = CbomBuilder.Build(new[] { Rsa("aa") }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");

        var cert = doc.Components.Single(c => c.BomRef == "cert:aa");
        cert.CryptoProperties!.AssetType.Should().Be("certificate");
        cert.CryptoProperties.CertificateProperties!.SignatureAlgorithmRef.Should().Be("alg:1.2.840.113549.1.1.11");
        cert.CryptoProperties.CertificateProperties.SubjectPublicKeyRef.Should().Be("key:aa");
        cert.CryptoProperties.CertificateProperties.NotValidBefore.Should().Be("2026-01-01T00:00:00Z");
        cert.CryptoProperties.CertificateProperties.NotValidAfter.Should().Be("2027-01-01T00:00:00Z");

        doc.Components.Should().Contain(c => c.BomRef == "alg:1.2.840.113549.1.1.11");
        doc.Components.Should().Contain(c => c.BomRef == "alg:1.2.840.113549.1.1.1");
        var key = doc.Components.Single(c => c.BomRef == "key:aa");
        key.CryptoProperties!.RelatedCryptoMaterialProperties!.Type.Should().Be("public-key");
        key.CryptoProperties.RelatedCryptoMaterialProperties.Size.Should().Be(4096);

        var dep = doc.Dependencies.Single(d => d.Ref == "cert:aa");
        dep.DependsOn.Should().Contain("alg:1.2.840.113549.1.1.11");
        dep.DependsOn.Should().Contain("key:aa");
    }

    [Fact]
    public void Deduplicates_shared_algorithm_components_across_certs()
    {
        var doc = CbomBuilder.Build(new[] { Rsa("aa"), Rsa("bb") }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");
        doc.Components.Count(c => c.BomRef == "alg:1.2.840.113549.1.1.11").Should().Be(1);
        doc.Components.Count(c => c.CryptoProperties?.AssetType == "certificate").Should().Be(2);
    }

    [Fact]
    public void Every_certificate_ref_resolves_to_a_component_bomref()
    {
        var doc = CbomBuilder.Build(new[] { Rsa("aa") }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");
        var bomRefs = doc.Components.Select(c => c.BomRef).ToHashSet();
        foreach (var dep in doc.Dependencies)
        {
            bomRefs.Should().Contain(dep.Ref);
            foreach (var on in dep.DependsOn) bomRefs.Should().Contain(on);
        }
    }

    [Fact]
    public void Hybrid_cert_emits_alt_signature_algorithm_and_has_no_orphaned_components()
    {
        var doc = CbomBuilder.Build(new[] { Hybrid("hh") }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");

        doc.Components.Should().Contain(c => c.BomRef == "alg:2.16.840.1.101.3.4.3.18");

        var certDep = doc.Dependencies.Single(d => d.Ref == "cert:hh");
        certDep.DependsOn.Should().Contain("alg:2.16.840.1.101.3.4.3.18");
        certDep.DependsOn.Should().OnlyHaveUniqueItems();

        // No orphaned alg:/key: components — every one is reachable via some dependsOn.
        var referenced = doc.Dependencies.SelectMany(d => d.DependsOn).ToHashSet();
        foreach (var comp in doc.Components.Where(c => c.BomRef.StartsWith("alg:") || c.BomRef.StartsWith("key:")))
            referenced.Should().Contain(comp.BomRef, $"component {comp.BomRef} should be reachable in the dependency graph");
    }

    [Fact]
    public void Two_certs_with_different_algorithms_yield_distinct_alg_components()
    {
        var doc = CbomBuilder.Build(new[] { Rsa("aa"), Ecdsa("bb") }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");
        doc.Components.Should().Contain(c => c.BomRef == "alg:1.2.840.113549.1.1.11");
        doc.Components.Should().Contain(c => c.BomRef == "alg:1.2.840.10045.4.3.2");
    }

    [Fact]
    public void Metadata_host_component_has_expected_bomref_and_name()
    {
        var doc = CbomBuilder.Build(new[] { Rsa("aa") }, "MYHOST", "2026-07-27T00:00:00Z", "1.0.0");
        doc.Metadata!.Component!.BomRef.Should().Be("host:MYHOST");
        doc.Metadata.Component.Name.Should().Be("MYHOST");
        doc.Metadata.Component.Type.Should().Be("platform");
    }

    [Fact]
    public void Duplicate_thumbprint_certs_are_emitted_once_with_unique_bomrefs()
    {
        var doc = CbomBuilder.Build(new[] { Rsa("dup"), Rsa("dup") }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");
        doc.Components.Count(c => c.CryptoProperties?.AssetType == "certificate").Should().Be(1);
        doc.Components.Count(c => c.CryptoProperties?.AssetType == "related-crypto-material").Should().Be(1);
        doc.Components.Select(c => c.BomRef).Should().OnlyHaveUniqueItems();
        doc.Dependencies.Select(d => d.Ref).Should().OnlyHaveUniqueItems();
    }

    private static DiscoveredCertificate RootCa(string thumb) => new(
        SubjectName: "CN=root", IssuerName: "CN=root", // self-signed
        NotBefore: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        NotAfter: new DateTime(2046, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        Sha256Thumbprint: thumb,
        SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
        SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",
        SubjectKeySizeBits: 4096,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "root.pfx",
        // digitalSignature=0, ..., keyCertSign=5, cRLSign=6
        KeyUsages: new[] { false, false, false, false, false, true, true, false, false },
        IsCertificateAuthority: true);

    private static DiscoveredCertificate ServerLeaf(string thumb) => Rsa(thumb) with
    {
        // digitalSignature=0, keyEncipherment=2, dataEncipherment=3
        KeyUsages = new[] { true, false, true, true, false, false, false, false, false },
        IsCertificateAuthority = false
    };

    [Fact]
    public void Emits_root_ca_role_and_signature_usage()
    {
        var doc = CbomBuilder.Build(new[] { RootCa("rr") }, "H", "2026-07-27T00:00:00Z", "1.0.0");

        var cert = doc.Components.Single(c => c.BomRef == "cert:rr");
        cert.Properties!.Single(p => p.Name == "certifactory:certificate:role").Value.Should().Be("root-ca");

        var key = doc.Components.Single(c => c.BomRef == "key:rr");
        key.Properties!.Single(p => p.Name == "certifactory:key:usage").Value.Should().Be("signature");
    }

    [Fact]
    public void Emits_leaf_role_and_both_usage()
    {
        var doc = CbomBuilder.Build(new[] { ServerLeaf("ll") }, "H", "2026-07-27T00:00:00Z", "1.0.0");

        var cert = doc.Components.Single(c => c.BomRef == "cert:ll");
        cert.Properties!.Single(p => p.Name == "certifactory:certificate:role").Value.Should().Be("leaf");

        var key = doc.Components.Single(c => c.BomRef == "key:ll");
        key.Properties!.Single(p => p.Name == "certifactory:key:usage").Value.Should().Be("both");
    }

    [Fact]
    public void Emits_crypto_functions_on_algorithm_components()
    {
        var doc = CbomBuilder.Build(new[] { Rsa("aa") }, "H", "2026-07-27T00:00:00Z", "1.0.0");
        var sigAlg = doc.Components.Single(c => c.BomRef == "alg:1.2.840.113549.1.1.11");
        sigAlg.CryptoProperties!.AlgorithmProperties!.CryptoFunctions.Should().Contain("sign");
    }
}
