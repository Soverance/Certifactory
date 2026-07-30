// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Soverance.Certifactory.Pq;
using BcX509 = Org.BouncyCastle.X509.X509Certificate;

/// <summary>
/// Turns a BouncyCastle certificate into a <see cref="DiscoveredCertificate"/>.
/// BouncyCastle is used (not X509Certificate2) so PQC certs parse reliably —
/// subject/issuer/validity/OIDs/SPKI are all available without .NET needing to
/// understand the key algorithm.
/// </summary>
public static class CertificateInspector
{
    public static DiscoveredCertificate Inspect(BcX509 cert, string sourceDescription, bool? hasPrivateKey)
    {
        var spki = cert.CertificateStructure.SubjectPublicKeyInfo;
        var subjectKeyAlgOid = spki.Algorithm.Algorithm.Id;

        int? keyBits = null;
        try
        {
            if (PublicKeyFactory.CreateKey(spki) is RsaKeyParameters rsa)
                keyBits = rsa.Modulus.BitLength;
        }
        catch
        {
            // PQC / unusual keys: leave size null and rely on the algorithm's
            // parameterSetIdentifier for sizing.
        }

        var sha256 = Convert.ToHexString(SHA256.HashData(cert.GetEncoded())).ToLowerInvariant();

        bool isHybrid = cert.GetExtensionValue(HybridExtensions.SubjectAltPublicKeyInfoOid) is not null;
        string? altSigAlgOid = null;
        string? altKeyAlgOid = null;
        if (isHybrid)
        {
            var altSpkiBytes = cert.GetExtensionValue(HybridExtensions.SubjectAltPublicKeyInfoOid);
            var altSpki = SubjectPublicKeyInfo.GetInstance(
                Asn1Object.FromByteArray(altSpkiBytes!.GetOctets()));
            altKeyAlgOid = altSpki.Algorithm.Algorithm.Id;

            var altAlgBytes = cert.GetExtensionValue(HybridExtensions.AltSignatureAlgorithmOid);
            if (altAlgBytes is not null)
            {
                var altAlg = AlgorithmIdentifier.GetInstance(
                    Asn1Object.FromByteArray(altAlgBytes.GetOctets()));
                altSigAlgOid = altAlg.Algorithm.Id;
            }
        }

        // KeyUsage bit array (BouncyCastle order: 0=digitalSignature, 1=nonRepudiation,
        // 2=keyEncipherment, 3=dataEncipherment, 4=keyAgreement, 5=keyCertSign,
        // 6=cRLSign, 7=encipherOnly, 8=decipherOnly), or null when the extension is absent.
        bool[]? keyUsages = cert.GetKeyUsage();

        // GetBasicConstraints() returns -1 when the cert is not a CA; any other value
        // (path length, or int.MaxValue for a CA with no path constraint) means CA.
        bool isCa = cert.GetBasicConstraints() != -1;

        return new DiscoveredCertificate(
            SubjectName: cert.SubjectDN.ToString(),
            IssuerName: cert.IssuerDN.ToString(),
            NotBefore: cert.NotBefore,
            NotAfter: cert.NotAfter,
            Sha256Thumbprint: sha256,
            SignatureAlgorithmOid: cert.SigAlgOid,
            SubjectKeyAlgorithmOid: subjectKeyAlgOid,
            SubjectKeySizeBits: keyBits,
            IsHybrid: isHybrid,
            AltSignatureAlgorithmOid: altSigAlgOid,
            AltKeyAlgorithmOid: altKeyAlgOid,
            SourceDescription: sourceDescription,
            KeyUsages: keyUsages,
            IsCertificateAuthority: isCa,
            HasPrivateKey: hasPrivateKey);
    }
}
