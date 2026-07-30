// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

public record ScanOptions(
    IReadOnlyList<string> Paths,
    string? PfxPasswordFile,
    bool IncludeSystemStores,
    string? OutputPath,
    bool Summary);

public sealed class ScanResult
{
    public required CbomDocument Document { get; init; }
    public List<string> Warnings { get; init; } = new();
}

/// <summary>
/// Orchestrates a scan: load certs from the given paths, inspect them, and build
/// a CBOM. Pure with respect to I/O side effects beyond reading the inputs — the
/// command layer owns writing output and printing the summary.
/// </summary>
public static class ScanRunner
{
    public static ScanResult Run(ScanOptions options, string hostName, string timestamp, string toolVersion)
    {
        var warnings = new List<string>();

        string? pfxPassword = null;
        if (options.PfxPasswordFile is not null)
        {
            if (File.Exists(options.PfxPasswordFile))
                pfxPassword = File.ReadAllText(options.PfxPasswordFile).Trim();
            else
                warnings.Add($"Password file not found: '{options.PfxPasswordFile}'. Encrypted keystores will be skipped.");
        }

        var loaded = new CertificateSourceResult();
        foreach (var path in options.Paths)
        {
            if (Directory.Exists(path))
                loaded.Merge(CertificateSource.LoadFromDirectory(path, pfxPassword));
            else if (File.Exists(path))
                loaded.Merge(CertificateSource.LoadFromPath(path, pfxPassword));
            else
                warnings.Add($"Path not found: '{path}'.");
        }

        if (options.IncludeSystemStores)
            loaded.Merge(CertificateStoreScanner.ScanDefault());

        warnings.AddRange(loaded.Warnings);

        var discovered = loaded.Certificates
            .Select(l => CertificateInspector.Inspect(l.Cert, l.SourceDescription, l.HasPrivateKey))
            .ToList();

        var deduped = new List<DiscoveredCertificate>();
        var seen = new Dictionary<string, int>();
        foreach (var d in discovered)
        {
            if (seen.TryGetValue(d.Sha256Thumbprint, out var count))
            {
                seen[d.Sha256Thumbprint] = count + 1;
            }
            else
            {
                seen[d.Sha256Thumbprint] = 1;
                deduped.Add(d);
            }
        }
        foreach (var d in deduped)
        {
            var n = seen[d.Sha256Thumbprint];
            if (n > 1)
                warnings.Add($"Certificate '{d.SubjectName}' was found at {n} locations; counted once.");
        }

        var doc = CbomBuilder.Build(deduped, hostName, timestamp, toolVersion);
        return new ScanResult { Document = doc, Warnings = warnings };
    }
}
