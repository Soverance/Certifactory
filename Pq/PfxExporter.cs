// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Pq;

using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

public static class PfxExporter
{
    private static readonly SecureRandom Random = new();

    /// <summary>
    /// Bundles a BC X509 cert + private key into a PFX byte array, then loads
    /// it as a .NET X509Certificate2 (the type the rest of the app uses).
    /// </summary>
    public static X509Certificate2 ToX509Certificate2(
        Org.BouncyCastle.X509.X509Certificate bcCert,
        AsymmetricKeyParameter privateKey,
        string friendlyName,
        string password)
    {
        var store = new Pkcs12StoreBuilder().Build();
        var certEntry = new X509CertificateEntry(bcCert);
        store.SetCertificateEntry(friendlyName, certEntry);
        store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey),
            new[] { certEntry });

        using var ms = new MemoryStream();
        store.Save(ms, password.ToCharArray(), Random);
        return new X509Certificate2(ms.ToArray(), password,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    /// <summary>
    /// Extracts a BouncyCastle keypair from a loaded .NET cert for use as
    /// an issuer signer when issuing leaf certs. RSA-only at this stage —
    /// Task 4.5 generalizes to handle PQ keys.
    /// </summary>
    public static AsymmetricCipherKeyPair ExtractKeyPair(X509Certificate2 cert)
    {
        // GetRsaKeyPair materializes the parameters into BC BigIntegers, so
        // disposing the underlying RSA instance after the call is safe.
        using var rsa = cert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException(
                "CA certificate has no RSA private key.");
        return DotNetUtilities.GetRsaKeyPair(rsa);
    }
}
