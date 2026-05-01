// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Soverance.Certifactory.Pq;
using Xunit;

namespace Certifactory.Tests;

public class CertificateBuilderTests
{
    [Fact]
    public void Builds_RSA_root_CA_with_self_signed_subject_and_basic_constraints()
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();

        var spec = new CertificateSpec(
            Purpose: CertificatePurpose.RootCa,
            CommonName: "test-root-ca",
            Password: "TestPass",
            Signer: signer,
            ServerIp: null,
            EmailAddress: null,
            Issuer: null);

        X509Certificate2 cert = CertificateBuilder.BuildCertificate(spec);

        cert.Subject.Should().Be("CN=test-root-ca");
        cert.Issuer.Should().Be("CN=test-root-ca");
        var bc = cert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Single();
        bc.CertificateAuthority.Should().BeTrue();
    }

    [Fact]
    public void Server_cert_signed_by_CA_chains_correctly()
    {
        var caSigner = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        caSigner.GenerateKeyPair();
        var caSpec = new CertificateSpec(
            CertificatePurpose.RootCa, "chain-test-ca", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null);
        var caCert = CertificateBuilder.BuildCertificate(caSpec);

        var leafSigner = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        leafSigner.GenerateKeyPair();
        var leafSpec = new CertificateSpec(
            CertificatePurpose.Server, "chain-test.example.com", "Pass", leafSigner,
            ServerIp: "10.0.0.1",
            EmailAddress: null,
            Issuer: new IssuerInfo(caCert, caSigner));
        var leaf = CertificateBuilder.BuildCertificate(leafSpec);

        leaf.Issuer.Should().Be("CN=chain-test-ca");
        leaf.Subject.Should().Be("CN=chain-test.example.com");

        leaf.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Should().ContainSingle();
        // Strong AKI assertion: the leaf's AuthorityKeyIdentifier.keyIdentifier
        // MUST equal the CA's SubjectKeyIdentifier — this is what makes the chain
        // actually validate, not just "AKI present somewhere".
        var caSki = caCert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single()
            .SubjectKeyIdentifierBytes;
        var leafAki = leaf.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().Single();
        leafAki.KeyIdentifier.Should().NotBeNull();
        leafAki.KeyIdentifier!.Value.ToArray().Should().Equal(caSki.ToArray());
        leaf.Extensions.OfType<X509BasicConstraintsExtension>().Single()
            .CertificateAuthority.Should().BeFalse();
    }

    [Fact]
    public void Smime_cert_includes_email_in_san_and_correct_eku()
    {
        var caSigner = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        caSigner.GenerateKeyPair();
        var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "smime-test-ca", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        var leafSigner = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        leafSigner.GenerateKeyPair();
        var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.Smime, "alice@example.com", "Pass", leafSigner,
            ServerIp: null,
            EmailAddress: "alice@example.com",
            Issuer: new IssuerInfo(caCert, caSigner)));

        leaf.Subject.Should().Contain("CN=alice@example.com");

        var ekus = leaf.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Single().EnhancedKeyUsages;
        ekus.OfType<Oid>()
            .Should().Contain(o => o.Value == "1.3.6.1.5.5.7.3.4"); // emailProtection

        var ku = leaf.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages;
        ku.Should().HaveFlag(X509KeyUsageFlags.DigitalSignature);
        ku.Should().HaveFlag(X509KeyUsageFlags.NonRepudiation);
        ku.Should().HaveFlag(X509KeyUsageFlags.KeyEncipherment);
        ku.Should().HaveFlag(X509KeyUsageFlags.DataEncipherment);

        var sanExt = leaf.Extensions.Single(e => e.Oid != null && e.Oid.Value == "2.5.29.17");
        var bcSan = Org.BouncyCastle.Asn1.X509.GeneralNames.GetInstance(
            Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(sanExt.RawData));
        var rfc822Names = bcSan.GetNames()
            .Where(n => n.TagNo == Org.BouncyCastle.Asn1.X509.GeneralName.Rfc822Name)
            .Select(n => n.Name.ToString());
        rfc822Names.Should().Contain("alice@example.com");
    }
}
