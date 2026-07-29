// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Remediate;

using System.Text;
using System.Text.Json;
using Soverance.Certifactory.Scan.Risk;

/// <summary>Renders a <see cref="RemediationPlan"/> as a console table, JSON, or a
/// shareable Markdown report. Rendering only — never recomputes.</summary>
public static class RemediationRenderer
{
    private const string CustodyNote =
        "Note: input CBOM lacked certificate custody enrichment; actionable assets " +
        "are listed as manual-review (cannot tell which keys you hold). Re-run via " +
        "`certifactory scan` to populate custody.";

    public static string Table(RemediationPlan p)
    {
        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine($"Remediation plan: {p.ControllableCount} controllable · " +
                      $"{p.VendorDependentCount} vendor-dependent · " +
                      $"{p.ManualReviewCount} manual-review · " +
                      $"{p.AlreadySafeCount} already safe  ({p.TotalAssets} assets)");
        if (!p.CustodyPresent) { sb.AppendLine(); sb.AppendLine(CustodyNote); }
        sb.AppendLine();

        if (p.Controllable.Count == 0)
        {
            sb.AppendLine("No controllable assets to reissue.");
            return sb.ToString();
        }

        int n = Math.Min(p.Options.TopN, p.Controllable.Count);
        sb.AppendLine($"Controllable — fix these (worst first), top {n}:");
        for (int i = 0; i < n; i++)
        {
            var r = p.Controllable[i];
            sb.AppendLine($"  {r.Score,5:0.0}  [{r.Grade}]  {r.Name}   reissue → {r.Target.ToAlgorithmId()}");
            sb.AppendLine($"            {r.CommandHint}");
        }
        return sb.ToString();
    }

    public static string Json(RemediationPlan p)
    {
        var projection = new
        {
            controllableCount = p.ControllableCount,
            vendorDependentCount = p.VendorDependentCount,
            manualReviewCount = p.ManualReviewCount,
            alreadySafeCount = p.AlreadySafeCount,
            totalAssets = p.TotalAssets,
            custodyPresent = p.CustodyPresent,
            timestamp = p.Timestamp,
            assets = p.All.Select(r => new
            {
                bomRef = r.BomRef,
                name = r.Name,
                score = r.Score,
                grade = r.Grade.ToString(),
                action = r.Action.ToString(),
                target = r.Target.ToAlgorithmId(),
                commandHint = r.CommandHint
            })
        };
        return JsonSerializer.Serialize(projection, new JsonSerializerOptions { WriteIndented = true });
    }

    public static string Markdown(RemediationPlan p)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Post-Quantum Remediation Plan");
        sb.AppendLine();
        sb.AppendLine($"Assessed {p.Timestamp} · {p.TotalAssets} assets  ");
        sb.AppendLine($"**{p.ControllableCount} controllable · {p.VendorDependentCount} vendor-dependent · " +
                      $"{p.ManualReviewCount} manual-review · {p.AlreadySafeCount} already safe**");
        sb.AppendLine();
        if (!p.CustodyPresent) { sb.AppendLine($"> {CustodyNote}"); sb.AppendLine(); }

        sb.AppendLine("## Controllable — Reissue as PQC");
        sb.AppendLine();
        sb.AppendLine("| # | Score | Grade | Asset | Target | Command |");
        sb.AppendLine("|---|---|---|---|---|---|");
        int n = Math.Min(p.Options.TopN, p.Controllable.Count);
        for (int i = 0; i < n; i++)
        {
            var r = p.Controllable[i];
            sb.AppendLine($"| {i + 1} | {r.Score:0.0} | {r.Grade} | {r.Name} | {r.Target.ToAlgorithmId()} | `{r.CommandHint}` |");
        }
        sb.AppendLine();
        sb.AppendLine("## Monitoring");
        sb.AppendLine();
        sb.AppendLine($"{p.VendorDependentCount} vendor-dependent trust anchor(s) — await a vendor PQC root; " +
                      "no direct action. See the full JSON output for the itemized list.");
        return sb.ToString();
    }
}
