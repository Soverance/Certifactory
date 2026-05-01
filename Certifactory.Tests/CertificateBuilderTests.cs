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
}
