// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Remediate;

using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan.Risk;

/// <summary>What to do about one asset.</summary>
public enum RemediationAction { ReissuePqc, MonitorVendor, ManualReview, AlreadyHybrid, None }

/// <summary>Recommended PQC target for a controllable asset (maps to KnownAlgorithms).</summary>
public enum TargetAlgorithm { None, MlDsa65, SlhDsa256s, Hybrid }

public static class TargetAlgorithmExtensions
{
    public static string ToAlgorithmId(this TargetAlgorithm t) => t switch
    {
        TargetAlgorithm.MlDsa65    => KnownAlgorithms.MlDsa65,
        TargetAlgorithm.SlhDsa256s => KnownAlgorithms.SlhDsa256s,
        TargetAlgorithm.Hybrid     => KnownAlgorithms.Hybrid,
        _                          => ""
    };
}

/// <summary>One asset's remediation verdict. CommandHint is set only for ReissuePqc.</summary>
public record RemediationItem(
    string BomRef,
    string Name,
    double Score,
    char Grade,
    RemediationAction Action,
    TargetAlgorithm Target,
    string? CommandHint);

/// <summary>The full playbook: every asset plus the controllable worst-first shortlist.</summary>
public record RemediationPlan(
    int TotalAssets,
    int ControllableCount,
    int VendorDependentCount,
    int ManualReviewCount,
    int AlreadySafeCount,
    IReadOnlyList<RemediationItem> Controllable,
    IReadOnlyList<RemediationItem> All,
    RiskOptions Options,
    string Timestamp,
    bool CustodyPresent);
