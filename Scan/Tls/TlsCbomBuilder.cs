// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Tls;

using Soverance.Certifactory.Scan;

/// <summary>
/// Builds a CycloneDX 1.6 CBOM from TLS endpoint probe results. Served certificate
/// chains are routed through the shipped CbomBuilder (so cert/key/algorithm modeling
/// and dedup are identical to the file/store scan); each successful endpoint additionally
/// gets a protocol asset and a key-exchange algorithm asset wired by dependency.
/// </summary>
public static class TlsCbomBuilder
{
    public static CbomDocument Build(
        IEnumerable<TlsEndpointResult> endpoints,
        string hostName,
        string timestamp,
        string toolVersion)
    {
        var eps = endpoints.Where(e => e.Succeeded && e.Chain.Count > 0).ToList();

        // 1) Base doc from all served certs via the shipped pipeline — this yields
        // all cert:/key:/alg: components + deps + metadata, already deduped.
        var discovered = eps
            .SelectMany(e => e.Chain.Select(c => CertificateInspector.Inspect(c, $"tls:{e.Host}:{e.Port}", hasPrivateKey: null)))
            .ToList();
        var doc = CbomBuilder.Build(discovered, hostName, timestamp, toolVersion);

        // Dedup KEX algorithm components by KexClassifier's canonical (case-
        // normalized) group key, so endpoints reporting the same group with
        // different casing (e.g. "X25519" vs "x25519") collapse to a single
        // component. The bom-ref itself preserves the first-seen raw casing.
        var kexRefByGroup = new Dictionary<string, string>();

        foreach (var e in eps)
        {
            var protoRef = $"protocol:tls:{e.Host}:{e.Port}";
            var leaf = CertificateInspector.Inspect(e.Chain[0], $"tls:{e.Host}:{e.Port}", hasPrivateKey: null);
            var leafRef = "cert:" + leaf.Sha256Thumbprint;

            var dependsOn = new List<string>();

            if (!string.IsNullOrEmpty(e.KexGroup))
            {
                var k = KexClassifier.Classify(e.KexGroup!);
                if (!kexRefByGroup.TryGetValue(k.GroupName, out var kexRef))
                {
                    kexRef = "alg:kex:" + e.KexGroup;
                    kexRefByGroup[k.GroupName] = kexRef;
                    doc.Components.Add(new Component
                    {
                        Type = "cryptographic-asset",
                        BomRef = kexRef,
                        Name = k.DisplayName,
                        CryptoProperties = new CryptoProperties
                        {
                            AssetType = "algorithm",
                            AlgorithmProperties = new AlgorithmProperties
                            {
                                Primitive = "key-agree",
                                NistQuantumSecurityLevel = k.NistQuantumSecurityLevel
                            }
                        }
                    });
                }
                dependsOn.Add(kexRef);
            }

            dependsOn.Add(leafRef);

            doc.Components.Add(new Component
            {
                Type = "cryptographic-asset",
                BomRef = protoRef,
                Name = $"TLS {e.TlsVersion} @ {e.Host}:{e.Port}",
                CryptoProperties = new CryptoProperties
                {
                    AssetType = "protocol",
                    ProtocolProperties = new ProtocolProperties
                    {
                        Version = e.TlsVersion,
                        CipherSuites = string.IsNullOrEmpty(e.CipherSuite)
                            ? null
                            : new List<CipherSuite> { new() { Name = e.CipherSuite! } }
                    }
                }
            });

            doc.Dependencies.Add(new Dependency { Ref = protoRef, DependsOn = dependsOn });
        }

        return doc;
    }
}
