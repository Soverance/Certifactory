// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

using System.Text;
using Soverance.Certifactory.Scan.Tls;

public record PqReadinessCounts(
    int Vulnerable, int Transitional, int QuantumSafe,
    int CertificateCount, int KeyCount, int AlgorithmCount,
    int TlsEndpointCount = 0, int TlsVulnerableKex = 0, int TlsHybridKex = 0, int TlsSafeKex = 0);

/// <summary>
/// Derives a post-quantum readiness summary from a built CBOM and renders the
/// human table printed to stderr by `scan --summary`.
/// </summary>
public static class ScanSummary
{
    public static PqReadinessCounts Compute(CbomDocument doc)
    {
        var graph = new CbomGraph(doc);

        int vuln = 0, trans = 0, safe = 0, certs = 0;
        foreach (var comp in doc.Components)
        {
            if (comp.CryptoProperties?.AssetType != "certificate") continue;
            certs++;

            var readinesses = graph.AlgorithmsFor(comp.BomRef).Select(a => a.Readiness).ToList();
            bool hasVuln = readinesses.Contains(PqReadiness.Vulnerable);
            bool hasSafe = readinesses.Contains(PqReadiness.QuantumSafe);

            if (hasVuln && hasSafe) trans++;
            else if (hasSafe) safe++;
            else vuln++; // vulnerable or unknown-classical => pessimistic bucket
        }

        int keys = doc.Components.Count(c => c.CryptoProperties?.AssetType == "related-crypto-material");
        int algs = doc.Components.Count(c => c.CryptoProperties?.AssetType == "algorithm");

        int tlsEndpoints = 0, tlsVulnKex = 0, tlsHybridKex = 0, tlsSafeKex = 0;
        foreach (var comp in doc.Components)
        {
            if (comp.CryptoProperties?.AssetType != "protocol") continue;
            tlsEndpoints++;

            var kex = graph.KexFor(comp.BomRef);
            if (kex.IsHybrid) tlsHybridKex++;
            else if (kex.Readiness == PqReadiness.QuantumSafe) tlsSafeKex++;
            else tlsVulnKex++; // vulnerable or unknown group => pessimistic bucket
        }

        return new PqReadinessCounts(vuln, trans, safe, certs, keys, algs, tlsEndpoints, tlsVulnKex, tlsHybridKex, tlsSafeKex);
    }

    public static string Render(PqReadinessCounts c)
    {
        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine($"Scanned {c.CertificateCount} certificates | {c.KeyCount} keys | {c.AlgorithmCount} distinct algorithms");
        sb.AppendLine();
        sb.AppendLine("Post-quantum readiness");
        sb.AppendLine($"  [!]  {c.Vulnerable,3} quantum-vulnerable");
        sb.AppendLine($"  [~]  {c.Transitional,3} hybrid (transitional)");
        sb.AppendLine($"  [ok] {c.QuantumSafe,3} quantum-safe");

        if (c.TlsEndpointCount > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"TLS endpoints ({c.TlsEndpointCount} scanned)");
            sb.AppendLine($"  [!]  {c.TlsVulnerableKex,3} quantum-vulnerable key exchange");
            sb.AppendLine($"  [~]  {c.TlsHybridKex,3} hybrid key exchange (transitional)");
            sb.AppendLine($"  [ok] {c.TlsSafeKex,3} quantum-safe key exchange");
        }

        return sb.ToString();
    }
}
