// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Pq;

/// <summary>
/// Stable string identifiers for the algorithms supported by Certifactory.
/// Used by IPqSigner.AlgorithmId, SignerFactory dispatch, and the CLI --algorithm flag.
/// New algorithms get a const here as they're added.
/// </summary>
public static class KnownAlgorithms
{
    public const string Rsa4096 = "rsa-4096";
    public const string MlDsa65 = "ml-dsa-65";
    public const string SlhDsa256s = "slh-dsa-256s";

    // "hybrid" is the default composition (RSA-4096 + ML-DSA-65) and is reserved
    // as the alias semantic. Future compositions get specific algorithm strings
    // (e.g. "hybrid-rsa-slh-dsa") while "hybrid" continues pointing at the default.
    public const string Hybrid = "hybrid";
}
