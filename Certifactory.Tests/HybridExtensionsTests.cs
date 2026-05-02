// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Linq;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Soverance.Certifactory.Pq;
using Xunit;

namespace Certifactory.Tests;

public class HybridExtensionsTests
{
    [Fact]
    public void BuildSubjectAltPublicKeyInfo_emits_SPKI_with_correct_OID()
    {
        var altSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        altSigner.GenerateKeyPair();

        var spki = HybridExtensions.BuildSubjectAltPublicKeyInfo(altSigner);
        var seq = (Asn1Sequence)spki.ToAsn1Object();
        seq.Count.Should().Be(2); // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }

        var algId = AlgorithmIdentifier.GetInstance(seq[0]);
        algId.Algorithm.Id.Should().Be("2.16.840.1.101.3.4.3.18"); // FIPS 204 ML-DSA-65
    }

    [Fact]
    public void BuildAltSignatureAlgorithm_emits_AlgorithmIdentifier()
    {
        var altSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        altSigner.GenerateKeyPair();

        AlgorithmIdentifier algId = HybridExtensions.BuildAltSignatureAlgorithm(altSigner);
        algId.Algorithm.Id.Should().Be("2.16.840.1.101.3.4.3.18");
    }

    [Fact]
    public void BuildAltSignatureValue_wraps_bytes_in_BIT_STRING()
    {
        byte[] sigBytes = new byte[] { 0x01, 0x02, 0x03, 0xFF };
        DerBitString result = HybridExtensions.BuildAltSignatureValue(sigBytes);

        result.Should().NotBeNull();
        result.GetBytes().Should().Equal(sigBytes);
    }

    [Fact]
    public void Alt_extension_OIDs_match_X509_2019_spec()
    {
        HybridExtensions.SubjectAltPublicKeyInfoOid.Id.Should().Be("2.5.29.72");
        HybridExtensions.AltSignatureAlgorithmOid.Id.Should().Be("2.5.29.73");
        HybridExtensions.AltSignatureValueOid.Id.Should().Be("2.5.29.74");
    }

    [Fact]
    public void Hybrid_root_CA_carries_three_alt_extensions()
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Hybrid);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "hybrid-test-ca", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        cert.Extensions.Should().Contain(e => e.Oid != null && e.Oid.Value == "2.5.29.72"); // subjectAltPublicKeyInfo
        cert.Extensions.Should().Contain(e => e.Oid != null && e.Oid.Value == "2.5.29.73"); // altSignatureAlgorithm
        cert.Extensions.Should().Contain(e => e.Oid != null && e.Oid.Value == "2.5.29.74"); // altSignatureValue
    }

    [Fact]
    public void Hybrid_cert_primary_signature_is_classical_RSA()
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Hybrid);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "hybrid-classical-ca", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        // Primary signature OID should be sha256WithRSAEncryption — this is the
        // load-bearing assertion that catches the SPKI-derived-vs-factory-derived
        // signature algorithm bug (rsaEncryption is the KEY OID 1.2.840.113549.1.1.1;
        // sha256WithRSAEncryption is the SIGNATURE OID 1.2.840.113549.1.1.11).
        cert.SignatureAlgorithm.Value.Should().Be("1.2.840.113549.1.1.11");
    }

    [Fact]
    public void Hybrid_alt_extensions_are_non_critical()
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Hybrid);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "hybrid-noncrit-ca", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value is "2.5.29.72" or "2.5.29.73" or "2.5.29.74")
            {
                ext.Critical.Should().BeFalse(
                    $"alt-sig extension {ext.Oid.Value} must be non-critical for legacy compat");
            }
        }
    }

    [Fact]
    public void Hybrid_cert_legacy_RSA_validation_succeeds()
    {
        // Legacy validators (anything that uses .NET's built-in X509Chain with no
        // PQC awareness) should validate the primary RSA signature successfully.
        // This proves: (1) the primary signature was correctly computed over the
        // final TBS, (2) the OID in TBS.signature matches outer Certificate.signatureAlgorithm,
        // (3) the AKI on the leaf points at the CA's SKI, (4) the cert structure
        // is byte-valid for .NET's X509Chain parser.

        var caSigner = SignerFactory.Create(KnownAlgorithms.Hybrid);
        caSigner.GenerateKeyPair();
        var ca = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "legacy-test-ca", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        var leafSigner = SignerFactory.Create(KnownAlgorithms.Hybrid);
        leafSigner.GenerateKeyPair();
        var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.Server, "legacy.example.com", "Pass", leafSigner,
            ServerIp: "10.0.0.5",
            EmailAddress: null,
            Issuer: new IssuerInfo(ca, caSigner)));

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        bool ok = chain.Build(leaf);

        ok.Should().BeTrue(
            $"legacy chain build failed: {string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation))}");
    }

    [Fact]
    public void Hybrid_cert_alt_signature_verifies_against_alt_public_key()
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Hybrid);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "verify-alt-ca", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        // The alt sig was produced by signing the preTBS with this cert's own
        // alt private key (since it's self-signed). Verifying against the alt
        // pubkey from subjectAltPublicKeyInfo should succeed.
        HybridVerifier.VerifyAltSignature(cert).Should().BeTrue();
    }

    [Fact]
    public void VerifyAltSignature_throws_on_non_hybrid_cert()
    {
        // Plain RSA cert has no alt-sig extensions
        var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "non-hybrid-rsa-ca", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        Action act = () => HybridVerifier.VerifyAltSignature(cert);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*not a hybrid cert*");
    }

    [Fact]
    public void Hybrid_leaf_chain_validates_under_both_classical_and_PQ_paths()
    {
        // Build hybrid CA + hybrid leaf signed by it
        var caSigner = SignerFactory.Create(KnownAlgorithms.Hybrid);
        caSigner.GenerateKeyPair();
        var ca = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "hybrid-chain-ca", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        var leafSigner = SignerFactory.Create(KnownAlgorithms.Hybrid);
        leafSigner.GenerateKeyPair();
        var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.Server, "hybrid-leaf.example.com", "Pass", leafSigner,
            ServerIp: "10.0.0.6",
            EmailAddress: null,
            Issuer: new IssuerInfo(ca, caSigner)));

        // Classical path: legacy X509Chain validation
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.Build(leaf).Should().BeTrue(
            $"classical chain build failed: {string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation))}");

        // PQ alt-sig path: verify CA's self-signed alt sig + leaf's alt sig against CA's alt pubkey
        HybridVerifier.VerifyAltSignature(ca).Should().BeTrue(
            "self-signed CA alt sig must verify against its own alt pubkey");
        HybridVerifier.VerifyAltSignature(leaf, ca).Should().BeTrue(
            "leaf alt sig must verify against issuer CA's alt pubkey");
    }

    [Fact]
    public void VerifyAltSignature_2arg_returns_false_when_issuer_is_wrong_hybrid_CA()
    {
        // Build hybrid CA1 + hybrid leaf signed by CA1
        var ca1Signer = SignerFactory.Create(KnownAlgorithms.Hybrid);
        ca1Signer.GenerateKeyPair();
        var ca1 = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "wrong-issuer-ca1", "Pass", ca1Signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        var leafSigner = SignerFactory.Create(KnownAlgorithms.Hybrid);
        leafSigner.GenerateKeyPair();
        var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.Server, "wrong-issuer-leaf.example.com", "Pass", leafSigner,
            ServerIp: "10.0.0.7",
            EmailAddress: null,
            Issuer: new IssuerInfo(ca1, ca1Signer)));

        // Build an unrelated hybrid CA2 — its alt key did NOT sign the leaf
        var ca2Signer = SignerFactory.Create(KnownAlgorithms.Hybrid);
        ca2Signer.GenerateKeyPair();
        var ca2 = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "wrong-issuer-ca2", "Pass", ca2Signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        // Sanity: leaf verifies against the correct issuer
        HybridVerifier.VerifyAltSignature(leaf, ca1).Should().BeTrue();

        // Load-bearing: leaf does NOT verify against the wrong issuer's alt pubkey
        HybridVerifier.VerifyAltSignature(leaf, ca2).Should().BeFalse();
    }
}
