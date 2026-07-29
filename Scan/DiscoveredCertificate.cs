// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

/// <summary>
/// Normalized facts extracted from one certificate, independent of where it was
/// found. Consumed by <see cref="CbomBuilder"/> to emit CycloneDX components.
/// </summary>
public record DiscoveredCertificate(
    string SubjectName,
    string IssuerName,
    DateTime NotBefore,
    DateTime NotAfter,
    string Sha256Thumbprint,
    string SignatureAlgorithmOid,
    string SubjectKeyAlgorithmOid,
    int? SubjectKeySizeBits,
    bool IsHybrid,
    string? AltSignatureAlgorithmOid,
    string? AltKeyAlgorithmOid,
    string SourceDescription,
    bool[]? KeyUsages = null,
    bool IsCertificateAuthority = false);
