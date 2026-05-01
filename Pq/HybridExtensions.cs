// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Pq;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

/// <summary>
/// Encoders for the X.509:2019 alternative-signature extensions used to build
/// hybrid certs that carry a classical primary signature plus a PQ alt signature.
/// Backward-compatible: legacy verifiers ignore the three extensions (non-critical)
/// and validate the cert as a normal classical chain; PQ-aware verifiers can
/// extract and validate the alt chain via these extension fields.
/// </summary>
public static class HybridExtensions
{
    // X.509:2019 alt-extension OIDs (ITU-T X.509 (2019) Annex on alternative public-key extensions)
    public static readonly DerObjectIdentifier SubjectAltPublicKeyInfoOid =
        new DerObjectIdentifier("2.5.29.72");
    public static readonly DerObjectIdentifier AltSignatureAlgorithmOid =
        new DerObjectIdentifier("2.5.29.73");
    public static readonly DerObjectIdentifier AltSignatureValueOid =
        new DerObjectIdentifier("2.5.29.74");

    /// <summary>
    /// Builds the subjectAltPublicKeyInfo extension value (the alt public key
    /// encoded as a SubjectPublicKeyInfo SEQUENCE).
    /// </summary>
    /// <remarks>The signer must have called <see cref="IPqSigner.GenerateKeyPair"/>
    /// (or otherwise been initialized with a key pair) before invocation.</remarks>
    public static SubjectPublicKeyInfo BuildSubjectAltPublicKeyInfo(IPqSigner altSigner)
    {
        return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(altSigner.KeyPair.Public);
    }

    /// <summary>
    /// Builds the altSignatureAlgorithm extension value. This is the AlgorithmIdentifier
    /// for the alt sig — derived from the alt public key's SPKI algorithm field, since
    /// the alt sig algorithm is by definition the signing algorithm tied to the alt key.
    /// </summary>
    /// <remarks>The signer must have called <see cref="IPqSigner.GenerateKeyPair"/>
    /// (or otherwise been initialized with a key pair) before invocation.</remarks>
    public static AlgorithmIdentifier BuildAltSignatureAlgorithm(IPqSigner altSigner)
    {
        var spki = BuildSubjectAltPublicKeyInfo(altSigner);
        return spki.Algorithm;
    }

    /// <summary>
    /// Builds the altSignatureValue extension value (the alt signature bytes as a BIT STRING).
    /// </summary>
    public static DerBitString BuildAltSignatureValue(byte[] sigBytes)
    {
        return new DerBitString(sigBytes);
    }
}
