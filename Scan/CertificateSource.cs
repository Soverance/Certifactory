// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using BcX509 = Org.BouncyCastle.X509.X509Certificate;

/// <summary>One certificate loaded from a source, with a human-readable provenance string.</summary>
public record LoadedCertificate(BcX509 Cert, string SourceDescription, bool HasPrivateKey = false);

/// <summary>Result of loading one path/directory: the certs found plus non-fatal warnings.</summary>
public sealed class CertificateSourceResult
{
    public List<LoadedCertificate> Certificates { get; } = new();
    public List<string> Warnings { get; } = new();

    public void Merge(CertificateSourceResult other)
    {
        Certificates.AddRange(other.Certificates);
        Warnings.AddRange(other.Warnings);
    }
}

/// <summary>
/// Loads BouncyCastle certificates from files. Read-only: never returns private
/// keys. Encrypted PKCS#12 without a supplied password is skipped with a warning,
/// never a throw (honors the offline, never-prompt scan contract).
/// </summary>
public static class CertificateSource
{
    private static readonly string[] Extensions =
        { "*.pem", "*.crt", "*.cer", "*.der", "*.pfx", "*.p12" };

    public static CertificateSourceResult LoadFromPath(string path, string? pfxPassword)
    {
        var result = new CertificateSourceResult();
        var ext = Path.GetExtension(path).ToLowerInvariant();
        try
        {
            switch (ext)
            {
                case ".pfx":
                case ".p12":
                    LoadPkcs12(path, pfxPassword, result);
                    break;
                case ".der":
                    LoadDer(path, result);
                    break;
                default:
                    LoadPemOrDer(path, result);
                    break;
            }
        }
        catch (Exception ex)
        {
            result.Warnings.Add($"Failed to read '{path}': {ex.Message}");
        }
        return result;
    }

    public static CertificateSourceResult LoadFromDirectory(string dir, string? pfxPassword)
    {
        var result = new CertificateSourceResult();
        foreach (var pattern in Extensions)
            foreach (var file in Directory.EnumerateFiles(dir, pattern, SearchOption.AllDirectories))
                result.Merge(LoadFromPath(file, pfxPassword));
        return result;
    }

    private static void LoadPkcs12(string path, string? password, CertificateSourceResult result)
    {
        if (password is null)
        {
            result.Warnings.Add(
                $"Skipped encrypted keystore '{path}': no password supplied (pass --pfx-password-file to inventory it).");
            return;
        }
        var store = new Pkcs12StoreBuilder().Build();
        using var fs = File.OpenRead(path);
        try
        {
            store.Load(fs, password.ToCharArray());
        }
        catch (Exception)
        {
            result.Warnings.Add($"Skipped keystore '{path}': password did not decrypt it.");
            return;
        }
        foreach (string alias in store.Aliases)
        {
            var entry = store.GetCertificate(alias);
            if (entry?.Certificate is not null)
                result.Certificates.Add(new LoadedCertificate(
                    entry.Certificate, $"{path}#{alias}", store.IsKeyEntry(alias)));
        }
    }

    private static void LoadDer(string path, CertificateSourceResult result)
    {
        using var fs = File.OpenRead(path);
        var cert = new X509CertificateParser().ReadCertificate(fs);
        if (cert is not null)
            result.Certificates.Add(new LoadedCertificate(cert, path));
    }

    private static void LoadPemOrDer(string path, CertificateSourceResult result)
    {
        var text = File.ReadAllText(path);
        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            bool hasKey = text.Contains("PRIVATE KEY-----");
            using var reader = new StringReader(text);
            var pem = new PemReader(reader);
            object? obj;
            while ((obj = pem.ReadObject()) is not null)
            {
                if (obj is BcX509 cert)
                    result.Certificates.Add(new LoadedCertificate(cert, path, hasKey));
            }
        }
        else
        {
            LoadDer(path, result);
        }
    }
}
