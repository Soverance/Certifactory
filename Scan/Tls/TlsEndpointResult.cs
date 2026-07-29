// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Tls;

using BcX509 = Org.BouncyCastle.X509.X509Certificate;

/// <summary>Result of one TLS endpoint probe. On failure, Succeeded is false and
/// FailureReason explains why; the other fields are null/empty.</summary>
public record TlsEndpointResult(
    string Host,
    int Port,
    bool Succeeded,
    string? TlsVersion,
    string? CipherSuite,
    string? KexGroup,
    IReadOnlyList<BcX509> Chain,
    string? FailureReason);
