// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using FluentAssertions;
using Org.BouncyCastle.Security;
using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan;

public class CertificateInspectorTests
{
    private static Org.BouncyCastle.X509.X509Certificate Mint(string algorithm, string cn)
    {
        var signer = SignerFactory.Create(algorithm);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, cn, "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));
        return DotNetUtilities.FromX509Certificate(cert);
    }

    [Fact]
    public void Inspects_rsa_root_ca_fields()
    {
        var bc = Mint(KnownAlgorithms.Rsa4096, "inspect-rsa");
        var d = CertificateInspector.Inspect(bc, "test.pem");

        d.SubjectName.Should().Contain("inspect-rsa");
        d.IssuerName.Should().Contain("inspect-rsa"); // self-signed
        d.SignatureAlgorithmOid.Should().Be("1.2.840.113549.1.1.11");
        d.SubjectKeyAlgorithmOid.Should().Be("1.2.840.113549.1.1.1");
        d.SubjectKeySizeBits.Should().Be(4096);
        d.IsHybrid.Should().BeFalse();
        d.Sha256Thumbprint.Should().MatchRegex("^[0-9a-f]{64}$");
        var expectedThumb = System.Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(bc.GetEncoded())).ToLowerInvariant();
        d.Sha256Thumbprint.Should().Be(expectedThumb);
        d.AltSignatureAlgorithmOid.Should().BeNull();
        d.AltKeyAlgorithmOid.Should().BeNull();
        d.SourceDescription.Should().Be("test.pem");
    }

    [Fact]
    public void Inspects_ml_dsa_cert_with_null_key_size()
    {
        var bc = Mint(KnownAlgorithms.MlDsa65, "inspect-mldsa");
        var d = CertificateInspector.Inspect(bc, "src");

        d.SignatureAlgorithmOid.Should().Be("2.16.840.1.101.3.4.3.18");
        d.SubjectKeySizeBits.Should().BeNull(); // not an RSA modulus
        d.IsHybrid.Should().BeFalse();
        d.AltSignatureAlgorithmOid.Should().BeNull();
        d.AltKeyAlgorithmOid.Should().BeNull();
    }

    [Fact]
    public void Detects_hybrid_cert_and_reads_alt_algorithm_oids()
    {
        var bc = Mint(KnownAlgorithms.Hybrid, "inspect-hybrid");
        var d = CertificateInspector.Inspect(bc, "src");

        d.IsHybrid.Should().BeTrue();
        d.SignatureAlgorithmOid.Should().Be("1.2.840.113549.1.1.11");      // classical primary
        d.AltSignatureAlgorithmOid.Should().Be("2.16.840.1.101.3.4.3.18"); // ML-DSA-65 alt
        d.AltKeyAlgorithmOid.Should().Be("2.16.840.1.101.3.4.3.18");
    }
}
