// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

/// <summary>
/// Assembles discovered certificates into a CycloneDX 1.6 CBOM: one certificate
/// component per cert, deduplicated algorithm components (keyed by OID), a key
/// component per cert subject key, and a dependency graph wiring them together.
/// </summary>
public static class CbomBuilder
{
    public static CbomDocument Build(
        IEnumerable<DiscoveredCertificate> certs,
        string hostName,
        string timestamp,
        string toolVersion)
    {
        var components = new List<Component>();
        var dependencies = new List<Dependency>();
        var algComponents = new Dictionary<string, Component>(); // oid -> component (dedup)
        var seenCertThumbprints = new HashSet<string>();

        Component AlgorithmComponent(string oid)
        {
            if (algComponents.TryGetValue(oid, out var existing)) return existing;
            var cls = QuantumClassifier.Classify(oid);
            var comp = new Component
            {
                Type = "cryptographic-asset",
                BomRef = "alg:" + oid,
                Name = cls.Name,
                CryptoProperties = new CryptoProperties
                {
                    AssetType = "algorithm",
                    Oid = oid,
                    AlgorithmProperties = new AlgorithmProperties
                    {
                        Primitive = cls.Primitive,
                        ParameterSetIdentifier = cls.ParameterSetIdentifier,
                        NistQuantumSecurityLevel = cls.NistQuantumSecurityLevel,
                        CryptoFunctions = CryptoFunctionsFor(cls.Primitive)
                    }
                }
            };
            algComponents[oid] = comp;
            components.Add(comp);
            return comp;
        }

        foreach (var c in certs)
        {
            if (!seenCertThumbprints.Add(c.Sha256Thumbprint))
                continue;

            var certRef = "cert:" + c.Sha256Thumbprint;
            var keyRef = "key:" + c.Sha256Thumbprint;

            var sigAlg = AlgorithmComponent(c.SignatureAlgorithmOid);
            var keyAlg = AlgorithmComponent(c.SubjectKeyAlgorithmOid);
            Component? altSigAlg = c.IsHybrid && c.AltSignatureAlgorithmOid is not null
                ? AlgorithmComponent(c.AltSignatureAlgorithmOid) : null;
            Component? altKeyAlg = c.IsHybrid && c.AltKeyAlgorithmOid is not null
                ? AlgorithmComponent(c.AltKeyAlgorithmOid) : null;

            components.Add(new Component
            {
                Type = "cryptographic-asset",
                BomRef = certRef,
                Name = c.SubjectName,
                Properties = new List<Property>
                {
                    new() { Name = "certifactory:certificate:role", Value = RoleFor(c) }
                },
                CryptoProperties = new CryptoProperties
                {
                    AssetType = "certificate",
                    CertificateProperties = new CertificateProperties
                    {
                        SubjectName = c.SubjectName,
                        IssuerName = c.IssuerName,
                        NotValidBefore = Iso(c.NotBefore),
                        NotValidAfter = Iso(c.NotAfter),
                        SignatureAlgorithmRef = sigAlg.BomRef,
                        SubjectPublicKeyRef = keyRef,
                        CertificateFormat = "X.509"
                    }
                }
            });

            components.Add(new Component
            {
                Type = "cryptographic-asset",
                BomRef = keyRef,
                Name = keyAlg.Name + " public key",
                Properties = new List<Property>
                {
                    new() { Name = "certifactory:key:usage", Value = KeyUsageStringFor(c.KeyUsages) }
                },
                CryptoProperties = new CryptoProperties
                {
                    AssetType = "related-crypto-material",
                    RelatedCryptoMaterialProperties = new RelatedCryptoMaterialProperties
                    {
                        Type = "public-key",
                        AlgorithmRef = keyAlg.BomRef,
                        Size = c.SubjectKeySizeBits,
                        State = "active"
                    }
                }
            });

            var certDeps = new List<string> { sigAlg.BomRef, keyRef };
            if (altSigAlg is not null) certDeps.Add(altSigAlg.BomRef);
            if (altKeyAlg is not null && altKeyAlg.BomRef != altSigAlg?.BomRef)
                certDeps.Add(altKeyAlg.BomRef);
            dependencies.Add(new Dependency { Ref = certRef, DependsOn = certDeps });
            dependencies.Add(new Dependency { Ref = keyRef, DependsOn = new List<string> { keyAlg.BomRef } });
        }

        return new CbomDocument
        {
            Metadata = new Metadata
            {
                Timestamp = timestamp,
                Tools = new ToolsSection
                {
                    Components = new List<ToolComponent>
                    {
                        new() { Type = "application", Name = "certifactory", Version = toolVersion, Publisher = "Soverance Studios" }
                    }
                },
                Component = new Component { Type = "platform", BomRef = "host:" + hostName, Name = hostName }
            },
            Components = components,
            Dependencies = dependencies
        };
    }

    private static string Iso(DateTime dt) =>
        dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

    // Intrinsic capability of the primitive — CycloneDX cryptoFunctions enum values.
    private static List<string>? CryptoFunctionsFor(string primitive) => primitive switch
    {
        "signature" => new() { "sign", "verify" },
        "pke"       => new() { "encrypt", "decrypt", "keygen" },
        "kem"       => new() { "encapsulate", "decapsulate", "keygen" },
        _           => null
    };

    private static string RoleFor(DiscoveredCertificate c) =>
        c.IsCertificateAuthority
            ? (c.IssuerName == c.SubjectName ? "root-ca" : "intermediate-ca")
            : "leaf";

    // Map the X.509 KeyUsage bit array to a coarse usage class for HNDL scoring.
    private static string KeyUsageStringFor(bool[]? ku)
    {
        if (ku is null || ku.Length < 5) return "unknown";
        bool sig = ku[0] || ku[1] || ku[5] || ku[6];        // digitalSignature, nonRepudiation, keyCertSign, cRLSign
        bool ke  = ku[2] || ku[3] || ku[4];                 // keyEncipherment, dataEncipherment, keyAgreement
        return (sig, ke) switch
        {
            (true, true)  => "both",
            (false, true) => "key-establishment",
            (true, false) => "signature",
            _             => "unknown"
        };
    }
}
