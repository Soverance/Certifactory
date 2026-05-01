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
    /// Produces a PFX byte array from a BC X509 cert + private key. The
    /// resulting bytes are written directly to disk by CLI handlers — this
    /// avoids round-tripping through .NET's X509Certificate2.Export, which
    /// can't re-serialize ML-DSA / SLH-DSA private keys.
    /// </summary>
    public static byte[] ToPfxBytes(
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
        return ms.ToArray();
    }

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
        byte[] bytes = ToPfxBytes(bcCert, privateKey, friendlyName, password);
        return new X509Certificate2(bytes, password,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    /// <summary>
    /// Extracts a BouncyCastle keypair from a PFX file for use as an issuer
    /// signer when issuing leaf certs. Uses BC's PKCS#12 parser directly so
    /// it works for ML-DSA / SLH-DSA / hybrid keys (which .NET's
    /// X509Certificate2 cannot re-export).
    ///
    /// If the PFX contains multiple key entries, the first one BC enumerates
    /// is returned. Certifactory-generated PFXs always contain exactly one.
    /// </summary>
    public static AsymmetricCipherKeyPair ExtractKeyPair(string pfxPath, string password)
    {
        ArgumentNullException.ThrowIfNull(pfxPath);
        ArgumentNullException.ThrowIfNull(password);
        using var fs = File.OpenRead(pfxPath);
        return ExtractKeyPair(fs, password);
    }

    /// <summary>
    /// Overload taking PFX bytes directly. Useful for tests and any caller
    /// that already holds the bytes in memory.
    /// </summary>
    public static AsymmetricCipherKeyPair ExtractKeyPair(byte[] pfxBytes, string password)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);
        ArgumentNullException.ThrowIfNull(password);
        using var ms = new MemoryStream(pfxBytes);
        return ExtractKeyPair(ms, password);
    }

    private static AsymmetricCipherKeyPair ExtractKeyPair(Stream pfxStream, string password)
    {
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(pfxStream, password.ToCharArray());

        foreach (string alias in store.Aliases)
        {
            if (store.IsKeyEntry(alias))
            {
                var keyEntry = store.GetKey(alias);
                var bcCert = store.GetCertificate(alias).Certificate;
                return new AsymmetricCipherKeyPair(bcCert.GetPublicKey(), keyEntry.Key);
            }
        }
        throw new InvalidOperationException(
            "PFX contains no private key entry. " +
            "Was the file generated without a private key, or is the password wrong?");
    }
}
