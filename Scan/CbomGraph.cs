// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

using Soverance.Certifactory.Scan.Tls;

/// <summary>
/// Read-only view over a CBOM's component + dependency graph. Resolves a
/// certificate (or key) component to the algorithm classifications it depends on,
/// and a TLS protocol component to its key-exchange classification. Duplicate
/// dependency refs are tolerated (first-seen wins) so a malformed doc never throws.
/// Shared by <see cref="ScanSummary"/> and the risk scorer.
/// </summary>
public sealed class CbomGraph
{
    private readonly Dictionary<string, List<string>> _dependsOn;
    private readonly Dictionary<string, Component> _byRef;

    public CbomGraph(CbomDocument doc)
    {
        _dependsOn = doc.Dependencies
            .GroupBy(d => d.Ref)
            .ToDictionary(g => g.Key, g => g.First().DependsOn);
        _byRef = doc.Components
            .GroupBy(c => c.BomRef)
            .ToDictionary(g => g.Key, g => g.First());
    }

    public IReadOnlyList<string> DependsOn(string bomRef)
        => _dependsOn.TryGetValue(bomRef, out var on) ? on : System.Array.Empty<string>();

    public Component? ComponentFor(string bomRef)
        => _byRef.TryGetValue(bomRef, out var c) ? c : null;

    public IReadOnlyList<AlgorithmClassification> AlgorithmsFor(string componentRef)
    {
        var result = new List<AlgorithmClassification>();
        foreach (var r in DependsOn(componentRef))
        {
            var comp = ComponentFor(r);
            var props = comp?.CryptoProperties;
            if (props?.AssetType == "algorithm" && props.Oid is not null)
            {
                result.Add(QuantumClassifier.Classify(props.Oid));
            }
            else if (props?.AssetType == "related-crypto-material")
            {
                foreach (var kr in DependsOn(r))
                {
                    var kc = ComponentFor(kr)?.CryptoProperties;
                    if (kc?.AssetType == "algorithm" && kc.Oid is not null)
                        result.Add(QuantumClassifier.Classify(kc.Oid));
                }
            }
        }
        return result;
    }

    public KexClassification KexFor(string protocolRef)
    {
        var kexRef = DependsOn(protocolRef).FirstOrDefault(r => r.StartsWith("alg:kex:"));
        var groupName = kexRef is not null ? kexRef["alg:kex:".Length..] : "";
        return KexClassifier.Classify(groupName);
    }
}
