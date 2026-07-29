// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Remediate;

/// <summary>
/// Maps a controllable, quantum-vulnerable asset to a recommended PQC target.
/// Precedence (first match wins): CA → ml-dsa-65; long-lived non-CA signing →
/// slh-dsa-256s; everything else (leaf / TLS endpoint) → hybrid for interop.
/// Single source of truth — extend here when Certifactory adds algorithms.
/// </summary>
public static class AlgorithmPolicy
{
    /// <summary>Validity span (years) at/above which a non-CA signing cert earns SLH-DSA.</summary>
    public const double LongValidityYears = 10.0;

    // role:  root-ca | intermediate-ca | leaf | tls-endpoint
    // usage: signature | key-establishment | both | unknown
    public static TargetAlgorithm Recommend(string role, string usage, double validitySpanYears)
    {
        if (role is "root-ca" or "intermediate-ca")
            return TargetAlgorithm.MlDsa65;
        if (validitySpanYears >= LongValidityYears && usage == "signature")
            return TargetAlgorithm.SlhDsa256s;
        return TargetAlgorithm.Hybrid;
    }

    /// <summary>Certifactory subcommand that reissues this role.</summary>
    public static string CommandName(string role) =>
        role is "root-ca" or "intermediate-ca" ? "ca" : "server";
}
