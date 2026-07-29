// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Linq;
using FluentAssertions;
using Org.BouncyCastle.Security;
using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan.Tls;
using Xunit;

namespace Certifactory.Tests.Scan.Tls;

public class TlsCbomBuilderTests
{
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
    public void Builds_protocol_asset_linked_to_kex_and_leaf_cert()
    {
        var ep = new TlsEndpointResult(
            "example.com", 443, Succeeded: true,
            TlsVersion: "1.3", CipherSuite: "TLS_AES_256_GCM_SHA384",
            KexGroup: "X25519MLKEM768",
            Chain: new[] { Leaf("example.com") },
            FailureReason: null);

        var doc = TlsCbomBuilder.Build(new[] { ep }, "SCANHOST", "2026-07-28T00:00:00Z", "1.0.0");

        var proto = doc.Components.Single(c => c.BomRef == "protocol:tls:example.com:443");
        proto.CryptoProperties!.AssetType.Should().Be("protocol");
        proto.CryptoProperties.ProtocolProperties!.Version.Should().Be("1.3");

        doc.Components.Should().Contain(c => c.BomRef == "alg:kex:X25519MLKEM768");
        doc.Components.Count(c => c.CryptoProperties?.AssetType == "certificate").Should().Be(1);

        var dep = doc.Dependencies.Single(d => d.Ref == "protocol:tls:example.com:443");
        dep.DependsOn.Should().Contain("alg:kex:X25519MLKEM768");
        dep.DependsOn.Should().Contain(r => r.StartsWith("cert:"));
        doc.Components.Select(c => c.BomRef).Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void Same_kex_group_in_different_casing_dedups_to_one_component()
    {
        var e1 = new TlsEndpointResult("a", 443, true, "1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", new[] { Leaf("a") }, null);
        var e2 = new TlsEndpointResult("b", 443, true, "1.3", "TLS_AES_256_GCM_SHA384", "x25519mlkem768", new[] { Leaf("b") }, null);
        var doc = TlsCbomBuilder.Build(new[] { e1, e2 }, "H", "2026-07-28T00:00:00Z", "1.0.0");

        doc.Components.Count(c => c.BomRef.StartsWith("alg:kex:")).Should().Be(1);
        doc.Components.Select(c => c.BomRef).Should().OnlyHaveUniqueItems();

        var kexRef = doc.Components.Single(c => c.BomRef.StartsWith("alg:kex:")).BomRef;
        foreach (var protoRef in new[] { "protocol:tls:a:443", "protocol:tls:b:443" })
            doc.Dependencies.Single(d => d.Ref == protoRef).DependsOn.Should().Contain(kexRef);
    }

    [Fact]
    public void Failed_endpoint_contributes_no_components()
    {
        var ep = new TlsEndpointResult("down.example.com", 443, false, null, null, null,
            System.Array.Empty<Org.BouncyCastle.X509.X509Certificate>(), "connection refused");
        var doc = TlsCbomBuilder.Build(new[] { ep }, "SCANHOST", "2026-07-28T00:00:00Z", "1.0.0");
        doc.Components.Should().NotContain(c => c.CryptoProperties != null && c.CryptoProperties.AssetType == "protocol");
    }
}
