// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Pq;

using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
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
    ///
    /// For hybrid certs, pass <paramref name="altPrivateKey"/> to also store
    /// the alt private key under a "<friendlyName>-alt" alias. Without this,
    /// a reloaded hybrid CA cannot issue more hybrid leaves (the alt key would
    /// be lost on disk).
    ///
    /// <para>
    /// Convention: the "-alt" suffix is reserved. Callers should not pass a
    /// <paramref name="friendlyName"/> ending in "-alt" since Task 6.8's loader
    /// uses that suffix to distinguish primary vs. alt key entries.
    /// </para>
    /// </summary>
    public static byte[] ToPfxBytes(
        Org.BouncyCastle.X509.X509Certificate bcCert,
        AsymmetricKeyParameter privateKey,
        string friendlyName,
        string password,
        AsymmetricKeyParameter? altPrivateKey = null)
    {
        var store = new Pkcs12StoreBuilder().Build();
        var certEntry = new X509CertificateEntry(bcCert);
        store.SetCertificateEntry(friendlyName, certEntry);
        store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey),
            new[] { certEntry });

        if (altPrivateKey is not null)
        {
            store.SetKeyEntry(friendlyName + "-alt",
                new AsymmetricKeyEntry(altPrivateKey),
                new[] { certEntry });
        }

        using var ms = new MemoryStream();
        store.Save(ms, password.ToCharArray(), Random);
        return ms.ToArray();
    }

    /// <summary>
    /// Bundles a BC X509 cert + private key into a PFX byte array, then loads
    /// it as a .NET X509Certificate2 (the type the rest of the app uses).
    /// For hybrid certs, pass <paramref name="altPrivateKey"/> to also embed
    /// the alt private key in the PKCS#12 store.
    /// </summary>
    public static X509Certificate2 ToX509Certificate2(
        Org.BouncyCastle.X509.X509Certificate bcCert,
        AsymmetricKeyParameter privateKey,
        string friendlyName,
        string password,
        AsymmetricKeyParameter? altPrivateKey = null)
    {
        byte[] bytes = ToPfxBytes(bcCert, privateKey, friendlyName, password, altPrivateKey);
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

    /// <summary>
    /// Extracts both primary and alt BouncyCastle keypairs from a hybrid PFX
    /// file. The primary key entry is under the cert's friendly name; the alt
    /// key entry is under "&lt;friendlyName&gt;-alt" (per Task 6.7's persistence
    /// convention). For non-hybrid PFX (no -alt entry, no subjectAltPublicKeyInfo
    /// extension), the returned <c>alt</c> tuple element is null.
    ///
    /// Algorithm-agnostic — works for RSA / ML-DSA / SLH-DSA / hybrid via BC's
    /// PKCS#12 parser. Avoids .NET's X509Certificate2.Export which can't re-serialize
    /// PQ private keys.
    /// </summary>
    public static (AsymmetricCipherKeyPair primary, AsymmetricCipherKeyPair? alt)
        ExtractHybridKeyPairs(string pfxPath, string password)
    {
        ArgumentNullException.ThrowIfNull(pfxPath);
        ArgumentNullException.ThrowIfNull(password);
        using var fs = File.OpenRead(pfxPath);
        return ExtractHybridKeyPairs(fs, password);
    }

    /// <summary>Bytes overload for tests / in-memory callers.</summary>
    public static (AsymmetricCipherKeyPair primary, AsymmetricCipherKeyPair? alt)
        ExtractHybridKeyPairs(byte[] pfxBytes, string password)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);
        ArgumentNullException.ThrowIfNull(password);
        using var ms = new MemoryStream(pfxBytes);
        return ExtractHybridKeyPairs(ms, password);
    }

    private static (AsymmetricCipherKeyPair primary, AsymmetricCipherKeyPair? alt)
        ExtractHybridKeyPairs(Stream pfxStream, string password)
    {
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(pfxStream, password.ToCharArray());

        // Find primary key entry (alias not ending in "-alt") and its associated cert
        AsymmetricCipherKeyPair? primary = null;
        Org.BouncyCastle.X509.X509Certificate? bcCert = null;
        foreach (string alias in store.Aliases)
        {
            if (store.IsKeyEntry(alias) && !alias.EndsWith("-alt"))
            {
                var keyEntry = store.GetKey(alias);
                bcCert = store.GetCertificate(alias).Certificate;
                primary = new AsymmetricCipherKeyPair(bcCert.GetPublicKey(), keyEntry.Key);
                break;
            }
        }
        if (primary is null)
            throw new InvalidOperationException(
                "PFX has no primary private key entry. " +
                "Was the file generated without a private key, or is the password wrong?");

        // Find alt key entry (alias ending in "-alt")
        AsymmetricKeyParameter? altPrivate = null;
        foreach (string alias in store.Aliases)
        {
            if (store.IsKeyEntry(alias) && alias.EndsWith("-alt"))
            {
                altPrivate = store.GetKey(alias).Key;
                break;
            }
        }

        AsymmetricCipherKeyPair? alt = null;
        if (altPrivate is not null && bcCert is not null)
        {
            // Pull the alt public key from the cert's subjectAltPublicKeyInfo extension
            var altSpkiBytes = bcCert.GetExtensionValue(HybridExtensions.SubjectAltPublicKeyInfoOid);
            if (altSpkiBytes is not null)
            {
                var altSpki = SubjectPublicKeyInfo.GetInstance(
                    Asn1Object.FromByteArray(altSpkiBytes.GetOctets()));
                var altPublic = PublicKeyFactory.CreateKey(altSpki);
                alt = new AsymmetricCipherKeyPair(altPublic, altPrivate);
            }
        }

        return (primary, alt);
    }
}
