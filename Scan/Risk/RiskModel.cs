// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Risk;

/// <summary>Post-quantum readiness bucket used to gate an asset's risk score.</summary>
public enum RiskReadiness { Vulnerable, Unknown, Hybrid, QuantumSafe }

/// <summary>The individual factor sub-scores that produced an asset's exposure.</summary>
public record FactorBreakdown(
    double Usage, double Role, double Validity, double KeyStrength,
    double Exposure, double ReadinessFactor);

/// <summary>One scored asset (certificate or TLS endpoint).</summary>
public record AssetRisk(
    string BomRef,
    string Name,
    string AssetType,                       // "certificate" | "protocol"
    double Score,                           // 0-100
    char Grade,                             // A-F
    FactorBreakdown Factors,
    IReadOnlyList<string> Drivers);         // top 1-2 human-readable reasons

/// <summary>Operator-supplied knobs. Mosca overrides are null unless both
/// QuantumYear and DataShelfLife are supplied.</summary>
public record RiskOptions(
    int TopN = 20,
    int? QuantumYear = null,
    double? DataShelfLife = null,
    double MigrationYears = 1.0,
    double? FailOver = null);

/// <summary>The full assessment: per-asset risks plus the inventory roll-up.</summary>
public record RiskAssessment(
    double InventoryScore,
    char Grade,
    IReadOnlyList<AssetRisk> Assets,        // sorted worst-first
    IReadOnlyDictionary<char, int> BandCounts,
    RiskOptions Options,
    string Timestamp,
    bool EnrichmentPresent);

/// <summary>Maps a 0-100 score to an A-F grade and a human label.</summary>
public static class RiskGrade
{
    public static char For(double score) =>
        score <= 20 ? 'A' :
        score <= 40 ? 'B' :
        score <= 60 ? 'C' :
        score <= 80 ? 'D' : 'F';

    public static string Label(char grade) => grade switch
    {
        'A' => "Low",
        'B' => "Guarded",
        'C' => "Elevated",
        'D' => "High",
        'F' => "Critical",
        _   => "Unknown"
    };
}
