// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Tls;

using System.Collections.Concurrent;
using Soverance.Certifactory.Scan;

public record TlsScanOptions(
    IReadOnlyList<string> Targets,
    string? TargetsFile,
    string? OutputPath,
    bool Summary,
    int TimeoutSeconds,
    int Concurrency);

public sealed class TlsScanResult
{
    public required CbomDocument Document { get; init; }
    public List<string> Warnings { get; init; } = new();
}

/// <summary>Orchestrates TLS endpoint probing: resolves targets, probes with bounded
/// concurrency and a per-target timeout, aggregates warnings, and builds the CBOM.
/// Read-only w.r.t. the filesystem; the command layer owns output I/O.</summary>
public static class TlsScanRunner
{
    public static TlsScanResult Run(TlsScanOptions options, string hostName, string timestamp, string toolVersion)
    {
        var warnings = new List<string>();
        var targets = new List<(string Host, int Port)>();

        var raw = new List<string>(options.Targets);
        if (options.TargetsFile is not null)
        {
            if (File.Exists(options.TargetsFile))
            {
                try
                {
                    raw.AddRange(File.ReadAllLines(options.TargetsFile)
                        .Select(l => l.Trim())
                        .Where(l => l.Length > 0 && !l.StartsWith("#")));
                }
                catch (Exception ex)
                {
                    warnings.Add($"Failed to read targets file '{options.TargetsFile}': {ex.Message}");
                }
            }
            else
                warnings.Add($"Targets file not found: '{options.TargetsFile}'.");
        }

        var seen = new HashSet<(string Host, int Port)>();
        foreach (var t in raw)
        {
            var idx = t.LastIndexOf(':');
            if (idx <= 0 || !int.TryParse(t[(idx + 1)..], out var port) || port < 1 || port > 65535)
            {
                warnings.Add($"Malformed target '{t}' (expected host:port).");
                continue;
            }

            var host = t[..idx];

            // Dedup (case-insensitive host compare): a duplicate host:port target —
            // whether from a repeated arg or overlap between positional targets and
            // --targets-file — would otherwise produce two protocol assets sharing
            // the same bom-ref (invalid CBOM) and two Dependency entries with the
            // same Ref (ScanSummary.Compute throws on the duplicate key).
            if (!seen.Add((host.ToLowerInvariant(), port)))
            {
                continue;
            }

            targets.Add((host, port));
        }

        var results = new ConcurrentBag<TlsEndpointResult>();
        var timeout = TimeSpan.FromSeconds(options.TimeoutSeconds <= 0 ? 10 : options.TimeoutSeconds);
        var maxDop = options.Concurrency <= 0 ? 8 : options.Concurrency;

        Parallel.ForEach(targets, new ParallelOptions { MaxDegreeOfParallelism = maxDop }, t =>
        {
            try
            {
                results.Add(TlsProbe.Probe(t.Host, t.Port, timeout));
            }
            catch (Exception ex)
            {
                results.Add(new TlsEndpointResult(
                    t.Host, t.Port, false, null, null, null,
                    Array.Empty<Org.BouncyCastle.X509.X509Certificate>(), ex.Message));
            }
        });

        foreach (var r in results.Where(r => !r.Succeeded))
            warnings.Add($"{r.Host}:{r.Port}: {r.FailureReason}");

        var doc = TlsCbomBuilder.Build(results, hostName, timestamp, toolVersion);
        return new TlsScanResult { Document = doc, Warnings = warnings };
    }
}
