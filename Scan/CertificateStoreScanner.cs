// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;

public record StoreLocationName(StoreLocation Location, StoreName Name);

/// <summary>
/// Enumerates certificates from OS trust stores. On Windows this reads the
/// standard X509Stores (including the People/Personal stores Certifactory installs
/// into); on Linux it falls back to well-known PEM directories. Read-only:
/// unreadable stores produce a warning, never an exception.
/// </summary>
public static class CertificateStoreScanner
{
    public static IReadOnlyList<StoreLocationName> DefaultWindowsStores { get; } = new[]
    {
        new StoreLocationName(StoreLocation.CurrentUser,  StoreName.My),
        new StoreLocationName(StoreLocation.CurrentUser,  StoreName.Root),
        new StoreLocationName(StoreLocation.CurrentUser,  StoreName.CertificateAuthority),
        new StoreLocationName(StoreLocation.CurrentUser,  StoreName.TrustedPeople),
        new StoreLocationName(StoreLocation.LocalMachine, StoreName.My),
        new StoreLocationName(StoreLocation.LocalMachine, StoreName.Root),
        new StoreLocationName(StoreLocation.LocalMachine, StoreName.CertificateAuthority),
        new StoreLocationName(StoreLocation.LocalMachine, StoreName.TrustedPeople),
    };

    public static CertificateSourceResult ScanDefault()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return ScanStores(DefaultWindowsStores);

        var result = new CertificateSourceResult();
        foreach (var dir in new[] { "/etc/ssl/certs", "/etc/pki/tls/certs" })
            if (Directory.Exists(dir))
                result.Merge(CertificateSource.LoadFromDirectory(dir, null));
        return result;
    }

    public static CertificateSourceResult ScanStores(IEnumerable<StoreLocationName> stores)
    {
        var result = new CertificateSourceResult();
        foreach (var s in stores)
            result.Merge(ScanOne(s.Location, s.Name.ToString(), () => new X509Store(s.Name, s.Location)));
        return result;
    }

    public static CertificateSourceResult ScanNamedStore(StoreLocation location, string storeName)
        => ScanOne(location, storeName, () => new X509Store(storeName, location));

    private static CertificateSourceResult ScanOne(StoreLocation location, string label, Func<X509Store> open)
    {
        var result = new CertificateSourceResult();
        try
        {
            using var store = open();
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var cert in store.Certificates)
            {
                try
                {
                    var bc = DotNetUtilities.FromX509Certificate(cert);
                    result.Certificates.Add(new LoadedCertificate(
                        bc, $"store:{location}/{label}", cert.HasPrivateKey));
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Could not read a cert in store {location}/{label}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            result.Warnings.Add($"Could not open store {location}/{label}: {ex.Message}");
        }
        return result;
    }
}
