// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

using System.Text;

public record PqReadinessCounts(
    int Vulnerable, int Transitional, int QuantumSafe,
    int CertificateCount, int KeyCount, int AlgorithmCount);

/// <summary>
/// Derives a post-quantum readiness summary from a built CBOM and renders the
/// human table printed to stderr by `scan --summary`.
/// </summary>
public static class ScanSummary
{
    public static PqReadinessCounts Compute(CbomDocument doc)
    {
        // Map alg bom-ref -> readiness (from the algorithm components' oid).
        var algReadiness = new Dictionary<string, PqReadiness>();
        foreach (var comp in doc.Components)
        {
            if (comp.CryptoProperties?.AssetType == "algorithm" && comp.CryptoProperties.Oid is not null)
                algReadiness[comp.BomRef] = QuantumClassifier.Classify(comp.CryptoProperties.Oid).Readiness;
        }

        var depsByRef = doc.Dependencies.ToDictionary(d => d.Ref, d => d.DependsOn);

        int vuln = 0, trans = 0, safe = 0, certs = 0;
        foreach (var comp in doc.Components)
        {
            if (comp.CryptoProperties?.AssetType != "certificate") continue;
            certs++;

            var referenced = depsByRef.TryGetValue(comp.BomRef, out var on) ? on : new List<string>();
            var readinesses = new List<PqReadiness>();
            foreach (var r in referenced)
            {
                if (algReadiness.TryGetValue(r, out var direct))
                {
                    readinesses.Add(direct); // r is an algorithm component (e.g. signature alg)
                }
                else if (depsByRef.TryGetValue(r, out var keyDeps))
                {
                    // r is a key (related-crypto-material) component; follow to its algorithm(s)
                    foreach (var kr in keyDeps)
                        if (algReadiness.TryGetValue(kr, out var keyAlgReadiness))
                            readinesses.Add(keyAlgReadiness);
                }
            }

            bool hasVuln = readinesses.Contains(PqReadiness.Vulnerable);
            bool hasSafe = readinesses.Contains(PqReadiness.QuantumSafe);

            if (hasVuln && hasSafe) trans++;
            else if (hasSafe) safe++;
            else vuln++; // vulnerable or unknown-classical => pessimistic bucket
        }

        int keys = doc.Components.Count(c => c.CryptoProperties?.AssetType == "related-crypto-material");
        int algs = doc.Components.Count(c => c.CryptoProperties?.AssetType == "algorithm");
        return new PqReadinessCounts(vuln, trans, safe, certs, keys, algs);
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
        return sb.ToString();
    }
}
