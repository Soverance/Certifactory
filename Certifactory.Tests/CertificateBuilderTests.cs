// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

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
}
