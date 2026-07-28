// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

/// <summary>Post-quantum posture of a cryptographic algorithm.</summary>
public enum PqReadiness
{
    /// <summary>Broken by a large-scale quantum computer (Shor): RSA, ECDSA, DH, ECDH.</summary>
    Vulnerable,
    /// <summary>A NIST PQC standard (FIPS 203/204/205).</summary>
    QuantumSafe,
    /// <summary>Not a public-key primitive whose posture we score (e.g. a bare hash, or unknown).</summary>
    NotApplicable
}

/// <summary>
/// Immutable classification of one algorithm, keyed by OID. Values map onto the
/// CycloneDX 1.6 algorithmProperties fields (primitive, nistQuantumSecurityLevel,
/// parameterSetIdentifier) plus our own readiness bucket for the summary.
/// </summary>
public record AlgorithmClassification(
    string Oid,
    string Name,
    string Primitive,
    PqReadiness Readiness,
    int NistQuantumSecurityLevel,
    string? ParameterSetIdentifier);

/// <summary>
/// Single source of truth mapping algorithm OIDs to their CBOM classification.
/// Covers the signature- and key-algorithm OIDs Certifactory itself emits, plus
/// the common classical algorithms a real host inventory turns up. Unknown OIDs
/// degrade gracefully to a NotApplicable, primitive="unknown" classification so
/// scanning never throws on an unrecognized asset.
/// </summary>
public static class QuantumClassifier
{
    private static readonly Dictionary<string, AlgorithmClassification> Table = Build();

    public static AlgorithmClassification Classify(string oid)
    {
        if (!string.IsNullOrEmpty(oid) && Table.TryGetValue(oid, out var hit))
            return hit;

        var safe = oid ?? "";
        return new AlgorithmClassification(
            Oid: safe,
            Name: $"Unknown ({safe})",
            Primitive: "unknown",
            Readiness: PqReadiness.NotApplicable,
            NistQuantumSecurityLevel: 0,
            ParameterSetIdentifier: null);
    }

    private static Dictionary<string, AlgorithmClassification> Build()
    {
        var t = new Dictionary<string, AlgorithmClassification>();

        void Add(string oid, string name, string primitive, PqReadiness r, int nist, string? param)
            => t[oid] = new AlgorithmClassification(oid, name, primitive, r, nist, param);

        // --- Classical, quantum-vulnerable ---
        Add("1.2.840.113549.1.1.1",  "RSA",               "pke",       PqReadiness.Vulnerable, 0, null); // rsaEncryption (key)
        Add("1.2.840.113549.1.1.11", "RSA with SHA-256",  "signature", PqReadiness.Vulnerable, 0, null); // sha256WithRSAEncryption
        Add("1.2.840.113549.1.1.12", "RSA with SHA-384",  "signature", PqReadiness.Vulnerable, 0, null);
        Add("1.2.840.113549.1.1.13", "RSA with SHA-512",  "signature", PqReadiness.Vulnerable, 0, null);
        Add("1.2.840.10045.2.1",     "EC public key",     "pke",       PqReadiness.Vulnerable, 0, null); // id-ecPublicKey (key)
        Add("1.2.840.10045.4.3.2",   "ECDSA with SHA-256","signature", PqReadiness.Vulnerable, 0, null);
        Add("1.2.840.10045.4.3.3",   "ECDSA with SHA-384","signature", PqReadiness.Vulnerable, 0, null);
        Add("1.2.840.10045.4.3.4",   "ECDSA with SHA-512","signature", PqReadiness.Vulnerable, 0, null);

        // --- NIST PQC standards, quantum-safe (FIPS 204 / 205) ---
        // ML-DSA parameter sets target NIST security categories 2/3/5.
        Add("2.16.840.1.101.3.4.3.17", "ML-DSA-44", "signature", PqReadiness.QuantumSafe, 2, "44");
        Add("2.16.840.1.101.3.4.3.18", "ML-DSA-65", "signature", PqReadiness.QuantumSafe, 3, "65");
        Add("2.16.840.1.101.3.4.3.19", "ML-DSA-87", "signature", PqReadiness.QuantumSafe, 5, "87");
        // SLH-DSA SHA2 parameter sets (small/fast omitted where not emitted by this tool).
        Add("2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s", "signature", PqReadiness.QuantumSafe, 1, "128s");
        Add("2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s", "signature", PqReadiness.QuantumSafe, 5, "256s");

        return t;
    }
}
