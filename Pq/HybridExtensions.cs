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

/// <summary>
/// Verifies the alt signature on a hybrid cert. Reconstructs the pre-TBS
/// (TBS minus altSignatureValue), then verifies the alt sig over that
/// against the alt public key from subjectAltPublicKeyInfo.
///
/// <para>
/// <b>Self-signed certs only.</b> This single-argument overload assumes the
/// issuer's alt public key equals the subject's alt public key (i.e. the cert
/// is self-signed). For leaf certs whose alt sig was produced by a hybrid CA's
/// alt private key, use the two-argument overload that takes the issuer cert
/// separately. (Added in Task 6.6.)
/// </para>
/// </summary>
public static class HybridVerifier
{
    /// <summary>
    /// Verifies the alt signature on a self-signed hybrid cert against its
    /// own alt public key (subject == issuer for self-signed). For a leaf or
    /// intermediate, use the two-argument overload.
    /// </summary>
    public static bool VerifyAltSignature(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        var bcCert = DotNetUtilities.FromX509Certificate(cert);
        if (!bcCert.IssuerDN.Equivalent(bcCert.SubjectDN))
        {
            throw new InvalidOperationException(
                "VerifyAltSignature(cert) only supports self-signed certs (subject == issuer). " +
                "For a leaf or intermediate cert, use VerifyAltSignature(cert, issuerCert).");
        }
        return VerifyAltSignature(cert, cert);
    }

    /// <summary>
    /// Verifies the alt signature on a hybrid cert against the issuer's alt
    /// public key. Reconstructs the cert's pre-TBS (TBS minus altSignatureValue)
    /// and verifies the alt sig over those bytes using the alt pubkey from the
    /// issuer's subjectAltPublicKeyInfo extension.
    ///
    /// For self-signed certs, pass the same cert as both arguments.
    /// </summary>
    /// <remarks>
    /// Returns false if the alt signature does not verify against the issuer's
    /// alt public key — for example, when the supplied issuer is the wrong
    /// hybrid CA. Throws only on malformed input (missing/partial alt extensions
    /// on cert, missing subjectAltPublicKeyInfo on issuer); a clean false is
    /// reserved for genuine cryptographic verification failure.
    /// </remarks>
    public static bool VerifyAltSignature(
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert,
        System.Security.Cryptography.X509Certificates.X509Certificate2 issuerCert)
    {
        var bcCert = DotNetUtilities.FromX509Certificate(cert);
        var bcIssuer = DotNetUtilities.FromX509Certificate(issuerCert);

        // Cert's 3 alt extensions
        var certSpkiBytes = bcCert.GetExtensionValue(HybridExtensions.SubjectAltPublicKeyInfoOid);
        var algIdBytes = bcCert.GetExtensionValue(HybridExtensions.AltSignatureAlgorithmOid);
        var sigValBytes = bcCert.GetExtensionValue(HybridExtensions.AltSignatureValueOid);

        bool certHasAny = certSpkiBytes is not null || algIdBytes is not null || sigValBytes is not null;
        bool certHasAll = certSpkiBytes is not null && algIdBytes is not null && sigValBytes is not null;

        if (!certHasAny)
        {
            throw new InvalidOperationException(
                "Cert has no alt-sig extensions; not a hybrid cert.");
        }
        if (!certHasAll)
        {
            throw new InvalidOperationException(
                "Cert is malformed: it has some but not all of the X.509:2019 alt-sig extensions " +
                "(subjectAltPublicKeyInfo / altSignatureAlgorithm / altSignatureValue).");
        }

        // Issuer must have subjectAltPublicKeyInfo (the alt pubkey we verify against).
        // For self-signed callers (cert == issuer), this is guaranteed non-null by the
        // certHasAll check above; kept here for symmetry with the leaf-verifying case.
        var issuerAltSpkiBytes = bcIssuer.GetExtensionValue(HybridExtensions.SubjectAltPublicKeyInfoOid);
        if (issuerAltSpkiBytes is null)
        {
            throw new InvalidOperationException(
                "Issuer cert has no subjectAltPublicKeyInfo extension; cannot verify a " +
                "hybrid leaf's alt signature without the issuer's alt public key. " +
                "Issuer is likely not a hybrid CA.");
        }

        var altAlg = AlgorithmIdentifier.GetInstance(
            Asn1Object.FromByteArray(algIdBytes!.GetOctets()));
        var altSigBits = DerBitString.GetInstance(
            Asn1Object.FromByteArray(sigValBytes!.GetOctets()));
        var issuerAltSpki = SubjectPublicKeyInfo.GetInstance(
            Asn1Object.FromByteArray(issuerAltSpkiBytes.GetOctets()));

        // Reconstruct preTBS = cert's TBS with altSignatureValue removed
        byte[] preTbsDer = ReconstructPreTbsForAltSig(bcCert.CertificateStructure.TbsCertificate);

        // Verify with BC's PublicKeyFactory + Asn1VerifierFactory using the
        // ISSUER's alt public key
        var altPublicKey = PublicKeyFactory.CreateKey(issuerAltSpki);
        var verifierFactory = new Asn1VerifierFactory(altAlg.Algorithm.Id, altPublicKey);
        var calc = verifierFactory.CreateCalculator();
        using (var s = calc.Stream)
        {
            s.Write(preTbsDer, 0, preTbsDer.Length);
        }
        return calc.GetResult().IsVerified(altSigBits.GetBytes());
    }

    /// <summary>
    /// Walks the cert's TBS extensions, drops altSignatureValue, re-encodes.
    /// Order-preserving: the resulting byte sequence must match exactly what
    /// the issuer's alt key originally signed (Task 6.3 step 2).
    /// </summary>
    private static byte[] ReconstructPreTbsForAltSig(TbsCertificateStructure tbs)
    {
        var origExts = tbs.Extensions;
        var newOrder = new List<DerObjectIdentifier>();
        var newDict = new Dictionary<DerObjectIdentifier, X509Extension>();
        // ExtensionOids returns OIDs in TBS-encoded order in BC 2.6.x; we rely on this for byte-identical re-encoding
        foreach (DerObjectIdentifier oid in origExts.ExtensionOids)
        {
            if (oid.Equals(HybridExtensions.AltSignatureValueOid)) continue;
            newOrder.Add(oid);
            newDict[oid] = origExts.GetExtension(oid);
        }
        var newExts = new X509Extensions(newOrder, newDict);

        var tbsGen = new V3TbsCertificateGenerator();
        tbsGen.SetSerialNumber(tbs.SerialNumber);
        tbsGen.SetIssuer(tbs.Issuer);
        tbsGen.SetSubject(tbs.Subject);
        tbsGen.SetStartDate(tbs.StartDate);
        tbsGen.SetEndDate(tbs.EndDate);
        // tbs.Signature is part of the signed bytes; passing it through is intentional
        tbsGen.SetSignature(tbs.Signature);
        tbsGen.SetSubjectPublicKeyInfo(tbs.SubjectPublicKeyInfo);
        tbsGen.SetExtensions(newExts);
        return tbsGen.GenerateTbsCertificate().GetDerEncoded();
    }
}
