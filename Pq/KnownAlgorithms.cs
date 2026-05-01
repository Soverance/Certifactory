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
}
