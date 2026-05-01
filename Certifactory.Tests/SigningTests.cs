// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using FluentAssertions;
using Org.BouncyCastle.Crypto;
using Soverance.Certifactory.Pq;
using Xunit;

namespace Certifactory.Tests;

public class SigningTests
{
    [Fact]
    public void RsaSigner_generates_4096_bit_key()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        signer.AlgorithmId.Should().Be(KnownAlgorithms.Rsa4096);
        signer.KeyPair.Should().NotBeNull();
        signer.KeyPair.Public.Should().NotBeNull();
        signer.KeyPair.Private.Should().NotBeNull();
    }

    [Fact]
    public void RsaSigner_creates_signature_factory()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        signer.CreateSignatureFactory().Should().NotBeNull();
    }

    [Fact]
    public void RsaSigner_KeyPair_throws_when_read_before_init()
    {
        var signer = new RsaSigner();
        Action act = () => _ = signer.KeyPair;
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void RsaSigner_CreateSignatureFactory_throws_before_init()
    {
        var signer = new RsaSigner();
        Action act = () => signer.CreateSignatureFactory();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void RsaSigner_GenerateKeyPair_twice_throws()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        Action act = () => signer.GenerateKeyPair();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void RsaSigner_LoadKeyPair_after_GenerateKeyPair_throws()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        var existingKeypair = signer.KeyPair;
        Action act = () => signer.LoadKeyPair(existingKeypair);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SignerFactory_creates_rsa_signer()
    {
        IPqSigner s = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        s.Should().BeOfType<RsaSigner>();
    }

    [Fact]
    public void SignerFactory_throws_on_unknown_algorithm()
    {
        Action act = () => SignerFactory.Create("bogus-algo");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*bogus-algo*")
            .WithMessage("*rsa-4096*");
    }

    [Fact]
    public void SignerFactory_throws_on_null_algorithm()
    {
        Action act = () => SignerFactory.Create(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void SignerFactory_SupportedAlgorithms_includes_rsa_4096()
    {
        SignerFactory.SupportedAlgorithms.Should().Contain(KnownAlgorithms.Rsa4096);
    }

    [Fact]
    public void MlDsaSigner_generates_keypair()
    {
        var signer = new MlDsaSigner();
        signer.GenerateKeyPair();
        signer.AlgorithmId.Should().Be(KnownAlgorithms.MlDsa65);
        signer.KeyPair.Should().NotBeNull();
        signer.KeyPair.Public.Should().NotBeNull();
        signer.KeyPair.Private.Should().NotBeNull();
    }

    [Fact]
    public void MlDsaSigner_creates_signature_factory()
    {
        var signer = new MlDsaSigner();
        signer.GenerateKeyPair();
        signer.CreateSignatureFactory().Should().NotBeNull();
    }

    [Fact]
    public void MlDsaSigner_factory_signs_and_verifies()
    {
        var signer = new MlDsaSigner();
        signer.GenerateKeyPair();

        byte[] message = "certifactory ml-dsa unit roundtrip"u8.ToArray();

        // Drive the IPqSigner's factory through a sign operation
        var factory = signer.CreateSignatureFactory();
        var calc = factory.CreateCalculator();
        using (var stream = calc.Stream)
        {
            stream.Write(message, 0, message.Length);
        }
        byte[] sig = calc.GetResult().Collect();
        sig.Should().NotBeNullOrEmpty();

        // Verify using BC's standalone ML-DSA verifier (independent code path)
        var bcVerifier = new Org.BouncyCastle.Crypto.Signers.MLDsaSigner(
            Org.BouncyCastle.Crypto.Parameters.MLDsaParameters.ml_dsa_65,
            deterministic: false);
        bcVerifier.Init(forSigning: false, signer.KeyPair.Public);
        bcVerifier.BlockUpdate(message, 0, message.Length);
        bcVerifier.VerifySignature(sig).Should().BeTrue();

        // And confirm a tampered message fails verification
        byte[] tampered = (byte[])message.Clone();
        tampered[0] ^= 0xFF;
        var bcVerifier2 = new Org.BouncyCastle.Crypto.Signers.MLDsaSigner(
            Org.BouncyCastle.Crypto.Parameters.MLDsaParameters.ml_dsa_65,
            deterministic: false);
        bcVerifier2.Init(forSigning: false, signer.KeyPair.Public);
        bcVerifier2.BlockUpdate(tampered, 0, tampered.Length);
        bcVerifier2.VerifySignature(sig).Should().BeFalse();
    }

    [Fact]
    public void MlDsaSigner_KeyPair_throws_when_read_before_init()
    {
        var signer = new MlDsaSigner();
        Action act = () => _ = signer.KeyPair;
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void MlDsaSigner_CreateSignatureFactory_throws_before_init()
    {
        var signer = new MlDsaSigner();
        Action act = () => signer.CreateSignatureFactory();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void MlDsaSigner_GenerateKeyPair_twice_throws()
    {
        var signer = new MlDsaSigner();
        signer.GenerateKeyPair();
        Action act = () => signer.GenerateKeyPair();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void MlDsaSigner_LoadKeyPair_after_GenerateKeyPair_throws()
    {
        var signer = new MlDsaSigner();
        signer.GenerateKeyPair();
        var existingKeypair = signer.KeyPair;
        Action act = () => signer.LoadKeyPair(existingKeypair);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SignerFactory_creates_ml_dsa_signer()
    {
        SignerFactory.Create(KnownAlgorithms.MlDsa65).Should().BeOfType<MlDsaSigner>();
    }

    [Fact]
    public void SignerFactory_SupportedAlgorithms_includes_ml_dsa_65()
    {
        SignerFactory.SupportedAlgorithms.Should().Contain(KnownAlgorithms.MlDsa65);
    }

    [Fact]
    public void CreateForCertificate_returns_RsaSigner_for_RSA_cert()
    {
        // build an RSA cert via CertificateBuilder, then re-detect via OID
        var caSigner = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        caSigner.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "test-rsa-detect", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        SignerFactory.CreateForCertificate(cert).Should().BeOfType<RsaSigner>();
    }

    [Fact]
    public void CreateForCertificate_returns_MlDsaSigner_for_ML_DSA_cert()
    {
        var caSigner = SignerFactory.Create(KnownAlgorithms.MlDsa65);
        caSigner.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "test-mldsa-detect", "Pass", caSigner,
            ServerIp: null, EmailAddress: null, Issuer: null));

        SignerFactory.CreateForCertificate(cert).Should().BeOfType<MlDsaSigner>();
    }

    [Fact]
    public void CreateForCertificate_throws_on_null()
    {
        Action act = () => SignerFactory.CreateForCertificate(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void SlhDsaSigner_generates_keypair()
    {
        var signer = new SlhDsaSigner();
        signer.GenerateKeyPair();
        signer.AlgorithmId.Should().Be(KnownAlgorithms.SlhDsa256s);
        signer.KeyPair.Should().NotBeNull();
        signer.KeyPair.Public.Should().NotBeNull();
        signer.KeyPair.Private.Should().NotBeNull();
    }

    [Fact]
    public void SlhDsaSigner_creates_signature_factory()
    {
        var signer = new SlhDsaSigner();
        signer.GenerateKeyPair();
        signer.CreateSignatureFactory().Should().NotBeNull();
    }

    [Fact]
    public void SlhDsaSigner_factory_signs_and_verifies()
    {
        var signer = new SlhDsaSigner();
        signer.GenerateKeyPair();

        byte[] message = "certifactory slh-dsa unit roundtrip"u8.ToArray();

        var factory = signer.CreateSignatureFactory();
        var calc = factory.CreateCalculator();
        using (var stream = calc.Stream)
        {
            stream.Write(message, 0, message.Length);
        }
        byte[] sig = calc.GetResult().Collect();
        sig.Should().NotBeNullOrEmpty();

        // Verify using BC's standalone SLH-DSA verifier (constructor takes (parameters, deterministic))
        var bcVerifier = new Org.BouncyCastle.Crypto.Signers.SlhDsaSigner(
            Org.BouncyCastle.Crypto.Parameters.SlhDsaParameters.slh_dsa_sha2_256s,
            deterministic: false);
        bcVerifier.Init(forSigning: false, signer.KeyPair.Public);
        bcVerifier.BlockUpdate(message, 0, message.Length);
        bcVerifier.VerifySignature(sig).Should().BeTrue();

        // And confirm a tampered message fails verification
        byte[] tampered = (byte[])message.Clone();
        tampered[0] ^= 0xFF;
        var bcVerifier2 = new Org.BouncyCastle.Crypto.Signers.SlhDsaSigner(
            Org.BouncyCastle.Crypto.Parameters.SlhDsaParameters.slh_dsa_sha2_256s,
            deterministic: false);
        bcVerifier2.Init(forSigning: false, signer.KeyPair.Public);
        bcVerifier2.BlockUpdate(tampered, 0, tampered.Length);
        bcVerifier2.VerifySignature(sig).Should().BeFalse();
    }

    [Fact]
    public void SlhDsaSigner_KeyPair_throws_when_read_before_init()
    {
        var signer = new SlhDsaSigner();
        Action act = () => _ = signer.KeyPair;
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SlhDsaSigner_CreateSignatureFactory_throws_before_init()
    {
        var signer = new SlhDsaSigner();
        Action act = () => signer.CreateSignatureFactory();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SlhDsaSigner_GenerateKeyPair_twice_throws()
    {
        var signer = new SlhDsaSigner();
        signer.GenerateKeyPair();
        Action act = () => signer.GenerateKeyPair();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SlhDsaSigner_LoadKeyPair_after_GenerateKeyPair_throws()
    {
        var signer = new SlhDsaSigner();
        signer.GenerateKeyPair();
        var existingKeypair = signer.KeyPair;
        Action act = () => signer.LoadKeyPair(existingKeypair);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SignerFactory_creates_slh_dsa_signer()
    {
        SignerFactory.Create(KnownAlgorithms.SlhDsa256s).Should().BeOfType<SlhDsaSigner>();
    }

    [Fact]
    public void SignerFactory_SupportedAlgorithms_includes_slh_dsa_256s()
    {
        SignerFactory.SupportedAlgorithms.Should().Contain(KnownAlgorithms.SlhDsa256s);
    }

    [Fact]
    public void HybridSigner_holds_primary_and_alt_signers()
    {
        var primary = new RsaSigner();
        primary.GenerateKeyPair();
        var alt = new MlDsaSigner();
        alt.GenerateKeyPair();

        var hybrid = new HybridSigner(primary, alt);
        hybrid.AlgorithmId.Should().Be(KnownAlgorithms.Hybrid);
        hybrid.PrimarySigner.Should().BeSameAs(primary);
        hybrid.AltSigner.Should().BeSameAs(alt);
    }

    [Fact]
    public void HybridSigner_GenerateKeyPair_initializes_both_inner_signers()
    {
        var primary = new RsaSigner();
        var alt = new MlDsaSigner();
        var hybrid = new HybridSigner(primary, alt);

        hybrid.GenerateKeyPair();

        primary.KeyPair.Should().NotBeNull();
        alt.KeyPair.Should().NotBeNull();
    }

    [Fact]
    public void HybridSigner_KeyPair_returns_primary_signers_keypair()
    {
        var primary = new RsaSigner();
        primary.GenerateKeyPair();
        var alt = new MlDsaSigner();
        alt.GenerateKeyPair();
        var hybrid = new HybridSigner(primary, alt);

        // KeyPair returns the PRIMARY keypair so the cert's SPKI is the
        // classical key — the alt key goes in subjectAltPublicKeyInfo.
        hybrid.KeyPair.Should().BeSameAs(primary.KeyPair);
    }

    [Fact]
    public void HybridSigner_LoadKeyPair_throws_NotSupportedException()
    {
        var primary = new RsaSigner();
        primary.GenerateKeyPair();
        var alt = new MlDsaSigner();
        alt.GenerateKeyPair();
        var hybrid = new HybridSigner(primary, alt);

        Action act = () => hybrid.LoadKeyPair(primary.KeyPair);
        act.Should().Throw<NotSupportedException>()
            .WithMessage("*primary and alt*");
    }

    [Fact]
    public void HybridSigner_CreateSignatureFactory_delegates_to_primary()
    {
        // The hybrid cert's primary signature (the load-bearing one for legacy
        // verifiers) is computed via PrimarySigner. The alt sig is computed
        // separately in Task 6.3's two-pass TBS path.
        var primary = new RsaSigner();
        primary.GenerateKeyPair();
        var alt = new MlDsaSigner();
        alt.GenerateKeyPair();
        var hybrid = new HybridSigner(primary, alt);

        hybrid.CreateSignatureFactory().Should().NotBeNull();
    }

    [Fact]
    public void SignerFactory_creates_hybrid_RSA_plus_ML_DSA_signer()
    {
        var s = SignerFactory.Create(KnownAlgorithms.Hybrid);
        s.Should().BeOfType<HybridSigner>();
        var h = (HybridSigner)s;
        h.PrimarySigner.Should().BeOfType<RsaSigner>();
        h.AltSigner.Should().BeOfType<MlDsaSigner>();
    }

    [Fact]
    public void SignerFactory_SupportedAlgorithms_includes_hybrid()
    {
        SignerFactory.SupportedAlgorithms.Should().Contain(KnownAlgorithms.Hybrid);
    }
}
