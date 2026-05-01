// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

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
}
