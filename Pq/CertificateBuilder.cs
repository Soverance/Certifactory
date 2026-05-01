// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Pq;

using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

public enum CertificatePurpose { RootCa, Server, Smime }

public sealed record CertificateSpec(
    CertificatePurpose Purpose,
    string CommonName,
    string Password,
    IPqSigner Signer,
    string? ServerIp,
    string? EmailAddress,
    IssuerInfo? Issuer);

public sealed record IssuerInfo(
    X509Certificate2 Certificate,
    IPqSigner Signer);

public static class CertificateBuilder
{
    private static readonly SecureRandom Random = new();

    /// <summary>
    /// Builds an X.509 certificate per <paramref name="spec"/>.
    /// Caller must initialize spec.Signer (call GenerateKeyPair or LoadKeyPair)
    /// before calling. For leaf certs (Issuer != null), the issuer signer must
    /// also be initialized with the CA's loaded private key.
    /// </summary>
    public static X509Certificate2 BuildCertificate(CertificateSpec spec)
    {
        ValidateSpec(spec);

        var gen = new X509V3CertificateGenerator();
        var subject = BuildSubject(spec);
        gen.SetSerialNumber(new BigInteger(159, Random).Abs().Add(BigInteger.One));
        gen.SetSubjectDN(subject);
        gen.SetIssuerDN(spec.Issuer is null
            ? subject
            : DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate).SubjectDN);
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(GetValidityDays(spec.Purpose)));
        gen.SetPublicKey(spec.Signer.KeyPair.Public);

        AddCommonExtensions(gen, spec);

        ISignatureFactory sigFactory = spec.Issuer is null
            ? spec.Signer.CreateSignatureFactory()
            : spec.Issuer.Signer.CreateSignatureFactory();

        Org.BouncyCastle.X509.X509Certificate bcCert = gen.Generate(sigFactory);

        return PfxExporter.ToX509Certificate2(
            bcCert, spec.Signer.KeyPair.Private, spec.CommonName, spec.Password);
    }

    private static X509Name BuildSubject(CertificateSpec spec) => spec.Purpose switch
    {
        CertificatePurpose.RootCa => new X509Name($"CN={spec.CommonName}"),
        CertificatePurpose.Server => new X509Name($"CN={spec.CommonName}"),
        CertificatePurpose.Smime  => new X509Name(
            $"CN={spec.CommonName},C=US,ST=Georgia,L=Atlanta,O=Soverance Studios,OU=Information"),
        _ => throw new ArgumentOutOfRangeException(nameof(spec))
    };

    private static int GetValidityDays(CertificatePurpose purpose) => purpose switch
    {
        CertificatePurpose.RootCa => 7300,  // 20 years
        CertificatePurpose.Server => 396,   // iOS limit
        CertificatePurpose.Smime  => 3650,  // 10 years
        _ => 365
    };

    private static void ValidateSpec(CertificateSpec spec)
    {
        if (spec.Purpose == CertificatePurpose.Smime && string.IsNullOrEmpty(spec.EmailAddress))
        {
            throw new ArgumentException(
                "S/MIME certificates require an email address.", nameof(spec));
        }
    }

    private static void AddCommonExtensions(
        X509V3CertificateGenerator gen, CertificateSpec spec)
    {
        // TODO(Task 6.3): SubjectKeyIdentifierStructure and AuthorityKeyIdentifierStructure
        // are [Obsolete] in BC 2.6.2 (replaced by X509ExtensionUtilities). Defer the
        // migration to Phase 6's CollectExtensions refactor, which restructures these
        // call sites anyway. Tracked: 5 CS0618 warnings.
        switch (spec.Purpose)
        {
            case CertificatePurpose.RootCa:
                gen.AddExtension(X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: true));
                gen.AddExtension(X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(spec.Signer.KeyPair.Public));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(new DerObjectIdentifier[]
                    {
                        KeyPurposeID.id_kp_serverAuth,
                        KeyPurposeID.id_kp_clientAuth,
                        KeyPurposeID.id_kp_codeSigning,
                        KeyPurposeID.id_kp_emailProtection,
                        new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12")
                    }));
                break;

            case CertificatePurpose.Server:
                gen.AddExtension(X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: false));
                gen.AddExtension(X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.DigitalSignature
                        | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth, KeyPurposeID.id_kp_clientAuth));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(spec.Signer.KeyPair.Public));
                if (spec.Issuer is not null)
                {
                    gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                        new AuthorityKeyIdentifierStructure(
                            DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate)));
                }
                AddServerSan(gen, spec);
                break;

            case CertificatePurpose.Smime:
                gen.AddExtension(X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: false));
                gen.AddExtension(X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.NonRepudiation | KeyUsage.DigitalSignature
                        | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(new DerObjectIdentifier[]
                    {
                        KeyPurposeID.id_kp_emailProtection,
                        new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12")
                    }));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(spec.Signer.KeyPair.Public));
                if (spec.Issuer is not null)
                {
                    gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                        new AuthorityKeyIdentifierStructure(
                            DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate)));
                }
                AddSmimeSan(gen, spec);
                break;
        }
    }

    private static void AddServerSan(X509V3CertificateGenerator gen, CertificateSpec spec)
    {
        var names = new List<GeneralName>
        {
            new GeneralName(GeneralName.DnsName, spec.CommonName)
        };
        if (!string.IsNullOrEmpty(spec.ServerIp))
        {
            names.Add(new GeneralName(GeneralName.IPAddress, spec.ServerIp));
        }
        gen.AddExtension(X509Extensions.SubjectAlternativeName, false,
            new GeneralNames(names.ToArray()));
    }

    private static void AddSmimeSan(X509V3CertificateGenerator gen, CertificateSpec spec)
    {
        var names = new[]
        {
            new GeneralName(GeneralName.Rfc822Name, spec.EmailAddress)
        };
        gen.AddExtension(X509Extensions.SubjectAlternativeName, false,
            new GeneralNames(names));
    }
}
