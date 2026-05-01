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

    [Fact]
    public void Builds_ML_DSA_root_CA_with_FIPS_204_signature_OID()
    {
        var signer = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        signer.GenerateKeyPair();
        var spec = new CertificateSpec(
            CertificatePurpose.RootCa, "ml-dsa-test-ca", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null);
        var cert = CertificateBuilder.BuildCertificate(spec);

        cert.Subject.Should().Be("CN=ml-dsa-test-ca");
        var bc = cert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Single();
        bc.CertificateAuthority.Should().BeTrue();
        cert.SignatureAlgorithm.Value.Should().NotBe("1.2.840.113549.1.1.11"); // not RSA-SHA256
        // ML-DSA-65 OID per FIPS 204: 2.16.840.1.101.3.4.3.18
        cert.SignatureAlgorithm.Value.Should().Be("2.16.840.1.101.3.4.3.18");

        // Verify the cert's signature actually validates against its embedded
        // public key — proves OID, key, and signature bytes are mutually
        // consistent (not just that the OID happens to be right).
        var bcCert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(cert);
        bcCert.Verify(bcCert.GetPublicKey()); // throws on bad sig
    }

    [Fact]
    public void ML_DSA_server_cert_signed_by_ML_DSA_CA_chains()
    {
        var caSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        caSigner.GenerateKeyPair();
        var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "ml-dsa-chain-ca", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        var leafSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        leafSigner.GenerateKeyPair();
        var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.Server, "ml-dsa.example.com", "Pass", leafSigner,
            ServerIp: "10.0.0.2",
            EmailAddress: null,
            Issuer: new IssuerInfo(caCert, caSigner)));

        leaf.Subject.Should().Be("CN=ml-dsa.example.com");
        leaf.Issuer.Should().Be("CN=ml-dsa-chain-ca");
        leaf.Extensions.OfType<X509BasicConstraintsExtension>().Single()
            .CertificateAuthority.Should().BeFalse();

        // AKI keyIdentifier matches CA's SKI bytes (proves chain link is real)
        var caSki = caCert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single()
            .SubjectKeyIdentifierBytes;
        var leafAki = leaf.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().Single();
        leafAki.KeyIdentifier.Should().NotBeNull();
        leafAki.KeyIdentifier!.Value.ToArray().Should().Equal(caSki.ToArray());

        // FIPS 204 ML-DSA-65 OID — better failure diagnostic than the BC verify alone
        leaf.SignatureAlgorithm.Value.Should().Be("2.16.840.1.101.3.4.3.18");

        // BC verify: the leaf's ML-DSA signature is genuinely valid against
        // the CA's ML-DSA public key (proves the chain signature is real)
        var bcLeaf = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(leaf);
        var bcCa = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(caCert);
        bcLeaf.Verify(bcCa.GetPublicKey()); // throws on bad sig
    }

    [Fact]
    public void ML_DSA_smime_cert_signed_by_ML_DSA_CA_chains()
    {
        var caSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        caSigner.GenerateKeyPair();
        var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "ml-dsa-smime-ca", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        var leafSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        leafSigner.GenerateKeyPair();
        var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.Smime, "bob@example.com", "Pass", leafSigner,
            ServerIp: null,
            EmailAddress: "bob@example.com",
            Issuer: new IssuerInfo(caCert, caSigner)));

        leaf.Subject.Should().Contain("CN=bob@example.com");
        leaf.Issuer.Should().Be("CN=ml-dsa-smime-ca");

        // emailProtection EKU
        var ekus = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages;
        ekus.OfType<Oid>().Should().Contain(o => o.Value == "1.3.6.1.5.5.7.3.4");

        // S/MIME KeyUsage flags
        var ku = leaf.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages;
        ku.Should().HaveFlag(X509KeyUsageFlags.DigitalSignature);
        ku.Should().HaveFlag(X509KeyUsageFlags.NonRepudiation);
        ku.Should().HaveFlag(X509KeyUsageFlags.KeyEncipherment);
        ku.Should().HaveFlag(X509KeyUsageFlags.DataEncipherment);

        // Email in rfc822Name SAN slot (per RFC 8551)
        var sanExt = leaf.Extensions.Single(e => e.Oid != null && e.Oid.Value == "2.5.29.17");
        var bcSan = Org.BouncyCastle.Asn1.X509.GeneralNames.GetInstance(
            Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(sanExt.RawData));
        var rfc822Names = bcSan.GetNames()
            .Where(n => n.TagNo == Org.BouncyCastle.Asn1.X509.GeneralName.Rfc822Name)
            .Select(n => n.Name.ToString());
        rfc822Names.Should().Contain("bob@example.com");

        // FIPS 204 ML-DSA-65 OID — better failure diagnostic than the BC verify alone
        leaf.SignatureAlgorithm.Value.Should().Be("2.16.840.1.101.3.4.3.18");

        // BC verify: leaf signature is valid against the CA's public key
        var bcLeaf = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(leaf);
        var bcCa = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(caCert);
        bcLeaf.Verify(bcCa.GetPublicKey()); // throws on bad sig
    }

    [Fact]
    public void BuildCertificateWithPfx_produces_loadable_PFX_for_ML_DSA()
    {
        var signer = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        signer.GenerateKeyPair();
        var (cert, pfxBytes) = CertificateBuilder.BuildCertificateWithPfx(new CertificateSpec(
            CertificatePurpose.RootCa, "test-mldsa-pfx-roundtrip", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        pfxBytes.Should().NotBeNullOrEmpty();
        cert.SignatureAlgorithm.Value.Should().Be("2.16.840.1.101.3.4.3.18");

        // Round-trip the BC-produced bytes through a fresh X509Certificate2 — this
        // confirms the PFX is well-formed and loadable by the .NET cert layer
        // (the .NET layer can READ ML-DSA PFXs, just can't re-Export them).
        using var reloaded = new X509Certificate2(pfxBytes, "Pass",
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
        reloaded.Thumbprint.Should().Be(cert.Thumbprint);
        reloaded.Subject.Should().Be("CN=test-mldsa-pfx-roundtrip");
    }

    [Fact]
    public void X509Certificate2_Export_throws_for_ML_DSA_certs()
    {
        // Regression sentinel: this is the exact failure mode that motivated the
        // BuildCertificateWithPfx + ToPfxBytes split. If a future .NET update adds
        // ML-DSA support to StorePal.Export, this test will fail and we can
        // simplify the API. Until then, the CLI MUST use BuildCertificateWithPfx
        // for the write path — calling cert.Export(X509ContentType.Pfx, ...) on
        // an ML-DSA cert throws CryptographicException.
        var signer = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "test-mldsa-export-throws", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        Action act = () => cert.Export(X509ContentType.Pfx, "Pass");
        act.Should().Throw<System.Security.Cryptography.CryptographicException>();
    }

    [Fact]
    public void ML_DSA_CA_roundtrips_through_PFX_and_can_sign_leaves()
    {
        // Build an ML-DSA CA, write its PFX to disk via the Task 4.4 pathway,
        // then reload via ExtractKeyPair and use the loaded keypair to sign
        // a leaf cert. This is the end-to-end roundtrip the CLI actually does.
        var caSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        caSigner.GenerateKeyPair();
        var (caCert, pfxBytes) = CertificateBuilder.BuildCertificateWithPfx(new CertificateSpec(
            CertificatePurpose.RootCa, "roundtrip-ca", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        var tempPath = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempPath, pfxBytes);

            // Reload as the CLI would
            using var reloaded = new X509Certificate2(tempPath, "Pass",
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

            // Detect algorithm + extract keypair from disk (the path Task 4.5 fixed)
            var detectedSigner = SignerFactory.CreateForCertificate(reloaded);
            detectedSigner.Should().BeOfType<MlDsaSigner>();
            detectedSigner.LoadKeyPair(PfxExporter.ExtractKeyPair(tempPath, "Pass"));

            // Issue a leaf cert from the reloaded CA
            var leafSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
            leafSigner.GenerateKeyPair();
            var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
                CertificatePurpose.Server, "leaf.example.com", "Pass", leafSigner,
                ServerIp: "10.0.0.3",
                EmailAddress: null,
                Issuer: new IssuerInfo(reloaded, detectedSigner)));

            leaf.Issuer.Should().Be("CN=roundtrip-ca");
            leaf.Subject.Should().Be("CN=leaf.example.com");

            // Load-bearing: leaf's ML-DSA signature was actually computed with
            // the CA's reloaded private key — proves the round-trip preserves
            // the key correctly.
            var bcLeaf = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(leaf);
            var bcCa = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(reloaded);
            bcLeaf.Verify(bcCa.GetPublicKey()); // throws on bad sig
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    [Fact]
    public void ExtractKeyPair_works_on_PFX_bytes_directly()
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();
        var (_, pfxBytes) = CertificateBuilder.BuildCertificateWithPfx(new CertificateSpec(
            CertificatePurpose.RootCa, "bytes-extract-test", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        var keypair = PfxExporter.ExtractKeyPair(pfxBytes, "Pass");
        keypair.Should().NotBeNull();
        keypair.Public.Should().NotBeNull();
        keypair.Private.Should().NotBeNull();
    }

    [Fact]
    public void CreateForCertificate_returns_SlhDsaSigner_for_SLH_DSA_cert()
    {
        var caSigner = SignerFactory.Create(KnownAlgorithms.SlhDsa256s);
        caSigner.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "test-slhdsa-detect", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        SignerFactory.CreateForCertificate(cert).Should().BeOfType<SlhDsaSigner>();
    }

    [Fact]
    public void Builds_SLH_DSA_root_CA_and_chains_to_SLH_DSA_leaf()
    {
        // Build the SLH-DSA root CA
        var caSigner = SignerFactory.Create(KnownAlgorithms.SlhDsa256s);
        caSigner.GenerateKeyPair();
        var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "slh-test-ca", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        // FIPS 205 SLH-DSA-SHA2-256s OID per NIST CSOR (.24, not .20 — that's the 128s variant)
        caCert.Subject.Should().Be("CN=slh-test-ca");
        caCert.SignatureAlgorithm.Value.Should().Be("2.16.840.1.101.3.4.3.24");
        caCert.Extensions.OfType<X509BasicConstraintsExtension>().Single()
            .CertificateAuthority.Should().BeTrue();

        // Verify the CA's signature actually validates against its embedded
        // public key — proves OID, key, and signature bytes are mutually
        // consistent (not just that the OID happens to be right).
        var bcCaCert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(caCert);
        bcCaCert.Verify(bcCaCert.GetPublicKey()); // throws on bad sig

        // Issue a leaf signed by the SLH-DSA CA
        var leafSigner = SignerFactory.Create(KnownAlgorithms.SlhDsa256s);
        leafSigner.GenerateKeyPair();
        var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.Server, "slh.example.com", "Pass", leafSigner,
            ServerIp: "10.0.0.4",
            EmailAddress: null,
            Issuer: new IssuerInfo(caCert, caSigner)));

        leaf.Subject.Should().Be("CN=slh.example.com");
        leaf.Issuer.Should().Be("CN=slh-test-ca");
        leaf.SignatureAlgorithm.Value.Should().Be("2.16.840.1.101.3.4.3.24");
        leaf.Extensions.OfType<X509BasicConstraintsExtension>().Single()
            .CertificateAuthority.Should().BeFalse();

        // AKI keyIdentifier matches CA's SKI bytes (proves chain link is real)
        var caSki = caCert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single()
            .SubjectKeyIdentifierBytes;
        var leafAki = leaf.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().Single();
        leafAki.KeyIdentifier.Should().NotBeNull();
        leafAki.KeyIdentifier!.Value.ToArray().Should().Equal(caSki.ToArray());

        // BC chain verify: the leaf's SLH-DSA signature is genuinely valid
        // against the CA's SLH-DSA public key (proves the chain signature is real)
        var bcLeaf = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(leaf);
        bcLeaf.Verify(bcCaCert.GetPublicKey()); // throws on bad sig
    }
}
