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
    /// Builds an X.509 certificate per <paramref name="spec"/>. Returns the
    /// .NET <see cref="X509Certificate2"/> for inspection (subject, extensions,
    /// thumbprint, etc.) — used primarily by tests.
    ///
    /// <para>
    /// <b>Do NOT call <see cref="X509Certificate2.Export(X509ContentType, string)"/>
    /// on the result with <see cref="X509ContentType.Pfx"/></b> — for ML-DSA / SLH-DSA
    /// certs, the .NET cert layer cannot re-serialize the private key and throws
    /// <see cref="System.Security.Cryptography.CryptographicException"/>. CLI code
    /// that needs to write the PFX to disk must use <see cref="BuildCertificateWithPfx"/>
    /// instead, which exposes the BC-produced bytes directly.
    /// </para>
    /// </summary>
    public static X509Certificate2 BuildCertificate(CertificateSpec spec)
    {
        var (cert, _) = BuildCertificateAndPfxInternal(spec);
        return cert;
    }

    /// <summary>
    /// Builds an X.509 certificate per <paramref name="spec"/> and returns
    /// both the loaded <see cref="X509Certificate2"/> (for inspection — e.g.
    /// thumbprint) and the BC-produced PFX bytes (for direct write to disk).
    /// CLI handlers must use this overload instead of calling
    /// <see cref="X509Certificate2.Export(X509ContentType, string)"/> on the
    /// returned cert, because .NET's StorePal cannot re-serialize ML-DSA /
    /// SLH-DSA private keys.
    /// </summary>
    public static (X509Certificate2 Certificate, byte[] PfxBytes) BuildCertificateWithPfx(CertificateSpec spec)
    {
        return BuildCertificateAndPfxInternal(spec);
    }

    private static (X509Certificate2 Certificate, byte[] PfxBytes) BuildCertificateAndPfxInternal(CertificateSpec spec)
    {
        ValidateSpec(spec);

        Org.BouncyCastle.X509.X509Certificate bcCert =
            spec.Signer is HybridSigner h
                ? BuildHybrid(spec, h)
                : BuildSinglePass(spec);

        // For hybrid, the PFX stores only the PRIMARY private key — the cert's
        // SPKI carries the primary public key, so the matching private is the
        // primary's. The ALT private key persistence is Task 6.7's scope.
        AsymmetricKeyParameter keyForPfx = spec.Signer is HybridSigner hs
            ? hs.PrimarySigner.KeyPair.Private
            : spec.Signer.KeyPair.Private;

        byte[] pfxBytes = PfxExporter.ToPfxBytes(
            bcCert, keyForPfx, spec.CommonName, spec.Password);
        var cert = new X509Certificate2(pfxBytes, spec.Password,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
        return (cert, pfxBytes);
    }

    private static Org.BouncyCastle.X509.X509Certificate BuildSinglePass(CertificateSpec spec)
    {
        var gen = new X509V3CertificateGenerator();
        var subject = BuildSubject(spec);
        var issuer = spec.Issuer is null
            ? subject
            : DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate).SubjectDN;

        gen.SetSerialNumber(new BigInteger(159, Random).Abs().Add(BigInteger.One));
        gen.SetSubjectDN(subject);
        gen.SetIssuerDN(issuer);
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(GetValidityDays(spec.Purpose)));
        gen.SetPublicKey(spec.Signer.KeyPair.Public);

        foreach (var (oid, critical, value) in CollectExtensions(spec))
        {
            gen.AddExtension(oid, critical, value);
        }

        ISignatureFactory sigFactory = spec.Issuer is null
            ? spec.Signer.CreateSignatureFactory()
            : spec.Issuer.Signer.CreateSignatureFactory();

        return gen.Generate(sigFactory);
    }

    private static Org.BouncyCastle.X509.X509Certificate BuildHybrid(
        CertificateSpec spec, HybridSigner subjectHybridSigner)
    {
        var subject = BuildSubject(spec);
        var issuer = spec.Issuer is null
            ? subject
            : DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate).SubjectDN;
        var serial = new BigInteger(159, Random).Abs().Add(BigInteger.One);

        // Determine the issuer's hybrid signer:
        //  - self-signed root CA: subject IS the issuer
        //  - leaf cert: must be issued by a hybrid CA (so we have an alt signer too)
        HybridSigner issuerHybridSigner;
        if (spec.Issuer is null)
        {
            issuerHybridSigner = subjectHybridSigner;
        }
        else if (spec.Issuer.Signer is HybridSigner h)
        {
            issuerHybridSigner = h;
        }
        else
        {
            throw new InvalidOperationException(
                "Hybrid leaf certificates require a hybrid issuer CA. " +
                "Issue this leaf from a CA that was generated with --algorithm hybrid.");
        }

        var exts = CollectExtensions(spec);

        return HybridCertificateBuilder.Build(
            subjectPrimarySigner: subjectHybridSigner.PrimarySigner,
            subjectAltSigner: subjectHybridSigner.AltSigner,
            issuerPrimarySigner: issuerHybridSigner.PrimarySigner,
            issuerAltSigner: issuerHybridSigner.AltSigner,
            subject: subject,
            issuer: issuer,
            serial: serial,
            notBefore: DateTime.UtcNow.AddDays(-1),
            notAfter: DateTime.UtcNow.AddDays(GetValidityDays(spec.Purpose)),
            normalExtensions: exts);
    }

    /// <summary>
    /// Returns the per-purpose extension list as (oid, critical, value) tuples.
    /// Both BuildSinglePass and BuildHybrid consume this — keep it the only
    /// source of cert-extension truth.
    /// </summary>
    private static List<(DerObjectIdentifier oid, bool critical, Asn1Encodable value)>
        CollectExtensions(CertificateSpec spec)
    {
        // For hybrid, the cert's standard SubjectKeyIdentifier and SPKI use
        // the PRIMARY public key (the alt key lives in subjectAltPublicKeyInfo).
        var pubKey = spec.Signer is HybridSigner hs
            ? hs.PrimarySigner.KeyPair.Public
            : spec.Signer.KeyPair.Public;
        var subjectSpki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);

        var list = new List<(DerObjectIdentifier, bool, Asn1Encodable)>();

        switch (spec.Purpose)
        {
            case CertificatePurpose.RootCa:
                list.Add((X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: true)));
                list.Add((X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign)));
                list.Add((X509Extensions.SubjectKeyIdentifier, false,
                    X509ExtensionUtilities.CreateSubjectKeyIdentifier(subjectSpki)));
                list.Add((X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(new DerObjectIdentifier[]
                    {
                        KeyPurposeID.id_kp_serverAuth,
                        KeyPurposeID.id_kp_clientAuth,
                        KeyPurposeID.id_kp_codeSigning,
                        KeyPurposeID.id_kp_emailProtection,
                        new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12")
                    })));
                break;

            case CertificatePurpose.Server:
                list.Add((X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: false)));
                list.Add((X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.DigitalSignature
                        | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment)));
                list.Add((X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth, KeyPurposeID.id_kp_clientAuth)));
                list.Add((X509Extensions.SubjectKeyIdentifier, false,
                    X509ExtensionUtilities.CreateSubjectKeyIdentifier(subjectSpki)));
                if (spec.Issuer is not null)
                {
                    var issuerSpki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                        DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate).GetPublicKey());
                    list.Add((X509Extensions.AuthorityKeyIdentifier, false,
                        X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuerSpki)));
                }
                list.Add((X509Extensions.SubjectAlternativeName, false,
                    BuildServerSan(spec)));
                break;

            case CertificatePurpose.Smime:
                list.Add((X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: false)));
                list.Add((X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.NonRepudiation | KeyUsage.DigitalSignature
                        | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment)));
                list.Add((X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(new DerObjectIdentifier[]
                    {
                        KeyPurposeID.id_kp_emailProtection,
                        new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12")
                    })));
                list.Add((X509Extensions.SubjectKeyIdentifier, false,
                    X509ExtensionUtilities.CreateSubjectKeyIdentifier(subjectSpki)));
                if (spec.Issuer is not null)
                {
                    var issuerSpki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                        DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate).GetPublicKey());
                    list.Add((X509Extensions.AuthorityKeyIdentifier, false,
                        X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuerSpki)));
                }
                list.Add((X509Extensions.SubjectAlternativeName, false,
                    new GeneralNames(new[]
                    {
                        new GeneralName(GeneralName.Rfc822Name, spec.EmailAddress)
                    })));
                break;
        }

        return list;
    }

    private static GeneralNames BuildServerSan(CertificateSpec spec)
    {
        var names = new List<GeneralName>
        {
            new GeneralName(GeneralName.DnsName, spec.CommonName)
        };
        if (!string.IsNullOrEmpty(spec.ServerIp))
        {
            names.Add(new GeneralName(GeneralName.IPAddress, spec.ServerIp));
        }
        return new GeneralNames(names.ToArray());
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
}
