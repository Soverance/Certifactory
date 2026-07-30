// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Certifactory.Tests.Scan;

using Soverance.Certifactory.Scan;
using Xunit;

public class CustodyEnrichmentTests
{
    private static DiscoveredCertificate Cert(bool? hasKey) => new(
        SubjectName: "CN=Owned", IssuerName: "CN=Owned",
        NotBefore: new DateTime(2020, 1, 1), NotAfter: new DateTime(2030, 1, 1),
        Sha256Thumbprint: hasKey switch { true => "aaaa", false => "bbbb", null => "cccc" },
        SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
        SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",
        SubjectKeySizeBits: 2048, IsHybrid: false,
        AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "test", KeyUsages: null, IsCertificateAuthority: false,
        HasPrivateKey: hasKey);

    [Fact]
    public void OwnedKeyCert_EmitsOwnedKeyCustody()
    {
        var doc = CbomBuilder.Build(new[] { Cert(hasKey: true) }, "host", "2026-07-29T00:00:00Z", "0.0.0");
        var comp = doc.Components.Single(c => c.BomRef == "cert:aaaa");
        var custody = comp.Properties!.Single(p => p.Name == "certifactory:certificate:custody");
        Assert.Equal("owned-key", custody.Value);
    }

    [Fact]
    public void PublicOnlyCert_EmitsPublicOnlyCustody()
    {
        var doc = CbomBuilder.Build(new[] { Cert(hasKey: false) }, "host", "2026-07-29T00:00:00Z", "0.0.0");
        var comp = doc.Components.Single(c => c.BomRef == "cert:bbbb");
        var custody = comp.Properties!.Single(p => p.Name == "certifactory:certificate:custody");
        Assert.Equal("public-only", custody.Value);
    }

    [Fact]
    public void UndeterminedCustodyCert_EmitsNoCustodyProperty_ButKeepsRole()
    {
        var doc = CbomBuilder.Build(new[] { Cert(hasKey: null) }, "host", "2026-07-29T00:00:00Z", "0.0.0");
        var comp = doc.Components.Single(c => c.BomRef == "cert:cccc");
        Assert.DoesNotContain(comp.Properties!, p => p.Name == "certifactory:certificate:custody");
        Assert.Contains(comp.Properties!, p => p.Name == "certifactory:certificate:role");
    }

    [Fact]
    public void PfxWithKey_LoadsAsOwnedKey_CerAsPublicOnly()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var signer = Soverance.Certifactory.Pq.SignerFactory.Create(
                Soverance.Certifactory.Pq.KnownAlgorithms.Rsa4096);
            signer.GenerateKeyPair();
            var (cert, pfx) = Soverance.Certifactory.Pq.CertificateBuilder.BuildCertificateWithPfx(
                new Soverance.Certifactory.Pq.CertificateSpec(
                    Soverance.Certifactory.Pq.CertificatePurpose.RootCa, "Fixture", "pw", signer,
                    ServerIp: null, EmailAddress: null, Issuer: null));
            var pfxPath = Path.Combine(dir, "f.pfx");
            File.WriteAllBytes(pfxPath, pfx);
            var cerPath = Path.Combine(dir, "f.cer");
            File.WriteAllBytes(cerPath, cert.RawData);

            var fromPfx = CertificateSource.LoadFromPath(pfxPath, "pw");
            var fromCer = CertificateSource.LoadFromPath(cerPath, null);

            Assert.All(fromPfx.Certificates, l => Assert.True(l.HasPrivateKey));
            Assert.All(fromCer.Certificates, l => Assert.False(l.HasPrivateKey));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
