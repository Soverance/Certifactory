// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Pq;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
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

/// <summary>
/// Builds hybrid X.509 certs via manual two-pass TBS construction. The cert
/// carries a classical primary signature plus a PQ alt signature embedded as
/// non-critical X.509:2019 extensions. Legacy verifiers ignore the unknown
/// extensions and validate the primary chain; PQ-aware verifiers extract and
/// validate the alt chain via the extensions.
///
/// Subject signers contribute the public keys (SPKI + subjectAltPublicKeyInfo).
/// Issuer signers actually sign. For self-signed certs, subject == issuer so
/// the same signers are passed in both roles.
/// </summary>
public static class HybridCertificateBuilder
{
    public static Org.BouncyCastle.X509.X509Certificate Build(
        IPqSigner subjectPrimarySigner,
        IPqSigner subjectAltSigner,
        IPqSigner issuerPrimarySigner,
        IPqSigner issuerAltSigner,
        X509Name subject,
        X509Name issuer,
        Org.BouncyCastle.Math.BigInteger serial,
        DateTime notBefore,
        DateTime notAfter,
        IList<(DerObjectIdentifier oid, bool critical, Asn1Encodable value)> normalExtensions)
    {
        // Build the signature factories ONCE — AlgorithmDetails is the canonical
        // source for both TBS.signature and outer Certificate.signatureAlgorithm.
        // Crucially, this is the SIGNATURE algorithm OID (e.g. sha256WithRSAEncryption
        // for RSA), NOT the public-key algorithm OID. For PQ algorithms they happen
        // to be the same OID; for RSA they differ, which is why we MUST use the
        // factory's AlgorithmDetails rather than deriving from SPKI.
        var primaryFactory = issuerPrimarySigner.CreateSignatureFactory();
        var altFactory = issuerAltSigner.CreateSignatureFactory();
        var primarySigAlg = (AlgorithmIdentifier)primaryFactory.AlgorithmDetails;
        var altSigAlg = (AlgorithmIdentifier)altFactory.AlgorithmDetails;

        // Step 1: build TBS WITH alt-pub-key + alt-algo extensions but
        //         WITHOUT alt-sig-value
        var allExtsForAltSig = new List<(DerObjectIdentifier, bool, Asn1Encodable)>(normalExtensions)
        {
            (HybridExtensions.SubjectAltPublicKeyInfoOid, false,
                HybridExtensions.BuildSubjectAltPublicKeyInfo(subjectAltSigner)),
            (HybridExtensions.AltSignatureAlgorithmOid, false, altSigAlg)
        };

        TbsCertificateStructure preTbs = BuildTbs(
            subjectPrimarySigner, primarySigAlg,
            subject, issuer, serial, notBefore, notAfter, allExtsForAltSig);

        // Step 2: sign preTbs with issuer's alt key
        byte[] altSig = SignBytes(altFactory, preTbs.GetDerEncoded());

        // Step 3: build final TBS with all three alt extensions
        var finalExts = new List<(DerObjectIdentifier, bool, Asn1Encodable)>(allExtsForAltSig)
        {
            (HybridExtensions.AltSignatureValueOid, false,
                HybridExtensions.BuildAltSignatureValue(altSig))
        };

        TbsCertificateStructure finalTbs = BuildTbs(
            subjectPrimarySigner, primarySigAlg,
            subject, issuer, serial, notBefore, notAfter, finalExts);

        // Step 4: sign final TBS with issuer's primary key
        byte[] primarySig = SignBytes(primaryFactory, finalTbs.GetDerEncoded());

        // Step 5: assemble Certificate ::= SEQUENCE { tbs, sigAlg, sigVal }
        var certSeq = new DerSequence(
            finalTbs,
            primarySigAlg,
            new DerBitString(primarySig));
        var certStruct = X509CertificateStructure.GetInstance(certSeq);
        return new Org.BouncyCastle.X509.X509Certificate(certStruct);
    }

    private static TbsCertificateStructure BuildTbs(
        IPqSigner subjectPrimarySigner,
        AlgorithmIdentifier signatureAlgorithm,
        X509Name subject,
        X509Name issuer,
        Org.BouncyCastle.Math.BigInteger serial,
        DateTime notBefore,
        DateTime notAfter,
        IList<(DerObjectIdentifier, bool, Asn1Encodable)> extensions)
    {
        // Subject's public key populates the cert's standard SubjectPublicKeyInfo
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
            subjectPrimarySigner.KeyPair.Public);

        var extDict = new Dictionary<DerObjectIdentifier, X509Extension>();
        var extOrder = new List<DerObjectIdentifier>();
        foreach (var (oid, critical, val) in extensions)
        {
            extOrder.Add(oid);
            extDict[oid] = new X509Extension(critical, new DerOctetString(val.GetDerEncoded()));
        }
        var x509Extensions = new X509Extensions(extOrder, extDict);

        var tbsGen = new V3TbsCertificateGenerator();
        tbsGen.SetSerialNumber(new DerInteger(serial));
        tbsGen.SetIssuer(issuer);
        tbsGen.SetSubject(subject);
        tbsGen.SetStartDate(new Time(notBefore));
        tbsGen.SetEndDate(new Time(notAfter));
        // tbs.signature must equal the SIGNATURE algorithm of whoever actually
        // signs the TBS (NOT the public-key algorithm of the subject)
        tbsGen.SetSignature(signatureAlgorithm);
        tbsGen.SetSubjectPublicKeyInfo(spki);
        tbsGen.SetExtensions(x509Extensions);
        return tbsGen.GenerateTbsCertificate();
    }

    private static byte[] SignBytes(ISignatureFactory factory, byte[] data)
    {
        var streamCalc = factory.CreateCalculator();
        using (var s = streamCalc.Stream)
        {
            s.Write(data, 0, data.Length);
        }
        return ((IBlockResult)streamCalc.GetResult()).Collect();
    }
}
