// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Tls;

/// <summary>Classification of a TLS key-exchange group's post-quantum posture.
/// Hybrid groups carry the classical bucket's "both present" semantics via IsHybrid,
/// mapping onto the same transitional rollup ScanSummary uses for hybrid certs.</summary>
public record KexClassification(
    string GroupName,
    string DisplayName,
    PqReadiness Readiness,
    bool IsHybrid,
    int NistQuantumSecurityLevel);

/// <summary>Maps TLS supported-group names to PQ readiness. Case-insensitive;
/// unknown groups degrade to NotApplicable and never throw.</summary>
public static class KexClassifier
{
    private static readonly Dictionary<string, KexClassification> Table = Build();

    public static KexClassification Classify(string groupName)
    {
        if (!string.IsNullOrEmpty(groupName) &&
            Table.TryGetValue(groupName.ToLowerInvariant(), out var hit))
            return hit;

        var safe = groupName ?? "";
        return new KexClassification(safe, $"Unknown ({safe})", PqReadiness.NotApplicable, false, 0);
    }

    private static Dictionary<string, KexClassification> Build()
    {
        var t = new Dictionary<string, KexClassification>();
        void Add(string name, string display, PqReadiness r, bool hybrid, int nist)
            => t[name] = new KexClassification(name, display, r, hybrid, nist);

        // Classical (Shor-breakable)
        Add("x25519", "X25519", PqReadiness.Vulnerable, false, 0);
        Add("x448", "X448", PqReadiness.Vulnerable, false, 0);
        Add("secp256r1", "secp256r1 (P-256)", PqReadiness.Vulnerable, false, 0);
        Add("secp384r1", "secp384r1 (P-384)", PqReadiness.Vulnerable, false, 0);
        Add("secp521r1", "secp521r1 (P-521)", PqReadiness.Vulnerable, false, 0);
        Add("ffdhe2048", "ffdhe2048", PqReadiness.Vulnerable, false, 0);
        Add("ffdhe3072", "ffdhe3072", PqReadiness.Vulnerable, false, 0);
        Add("ffdhe4096", "ffdhe4096", PqReadiness.Vulnerable, false, 0);
        Add("ffdhe6144", "ffdhe6144", PqReadiness.Vulnerable, false, 0);
        Add("ffdhe8192", "ffdhe8192", PqReadiness.Vulnerable, false, 0);

        // Hybrid (classical + PQ) — transitional
        Add("x25519mlkem768", "X25519MLKEM768", PqReadiness.QuantumSafe, true, 3);
        Add("secp256r1mlkem768", "SecP256r1MLKEM768", PqReadiness.QuantumSafe, true, 3);
        Add("secp384r1mlkem1024", "SecP384r1MLKEM1024", PqReadiness.QuantumSafe, true, 5);
        Add("x25519kyber768", "X25519Kyber768Draft00", PqReadiness.QuantumSafe, true, 3);

        // Pure PQ
        Add("mlkem768", "ML-KEM-768", PqReadiness.QuantumSafe, false, 3);
        Add("mlkem1024", "ML-KEM-1024", PqReadiness.QuantumSafe, false, 5);

        return t;
    }
}
