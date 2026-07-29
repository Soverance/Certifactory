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
        // Map alg bom-ref -> readiness (from the algorithm components' oid).
        var algReadiness = new Dictionary<string, PqReadiness>();
        foreach (var comp in doc.Components)
        {
            if (comp.CryptoProperties?.AssetType == "algorithm" && comp.CryptoProperties.Oid is not null)
                algReadiness[comp.BomRef] = QuantumClassifier.Classify(comp.CryptoProperties.Oid).Readiness;
        }

        // GroupBy(...).First() rather than ToDictionary(...) so a malformed doc with
        // duplicate dependency refs (e.g. duplicate tls-scan targets that slipped past
        // dedup) can never crash the summary — first-seen wins, matching ToDictionary's
        // behavior for the common case of unique refs.
        var depsByRef = doc.Dependencies.GroupBy(d => d.Ref).ToDictionary(g => g.Key, g => g.First().DependsOn);

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

        // TLS endpoint readiness: `protocol` components have no oid of their own
        // (TLS key-exchange groups aren't OID-addressable), so classify each one
        // by following its "alg:kex:" dependency through KexClassifier instead of
        // QuantumClassifier.
        int tlsEndpoints = 0, tlsVulnKex = 0, tlsHybridKex = 0, tlsSafeKex = 0;
        foreach (var comp in doc.Components)
        {
            if (comp.CryptoProperties?.AssetType != "protocol") continue;
            tlsEndpoints++;

            var referenced = depsByRef.TryGetValue(comp.BomRef, out var on) ? on : new List<string>();
            var kexRef = referenced.FirstOrDefault(r => r.StartsWith("alg:kex:"));
            var groupName = kexRef is not null ? kexRef["alg:kex:".Length..] : "";
            var kex = KexClassifier.Classify(groupName);

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
