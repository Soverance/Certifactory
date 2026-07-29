// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Risk;

using System.Text;
using System.Text.Json;

/// <summary>Renders a <see cref="RiskAssessment"/> as a console table, a JSON
/// report, or a shareable Markdown report. Rendering only — never recomputes.</summary>
public static class RiskReportRenderer
{
    private const string EnrichmentNote =
        "Note: input CBOM lacked certifactory enrichment (cert role / key usage); " +
        "scores use conservative worst-case defaults.";

    public static string Table(RiskAssessment a)
    {
        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine($"Post-quantum risk: {a.InventoryScore:0.0}/100  Grade {a.Grade} ({RiskGrade.Label(a.Grade)})");
        sb.AppendLine($"  F {a.BandCounts['F']}  D {a.BandCounts['D']}  C {a.BandCounts['C']}  B {a.BandCounts['B']}  A {a.BandCounts['A']}   ({a.Assets.Count} assets)");
        if (!a.EnrichmentPresent) { sb.AppendLine(); sb.AppendLine(EnrichmentNote); }
        sb.AppendLine();

        int n = Math.Min(a.Options.TopN, a.Assets.Count);
        sb.AppendLine($"Top {n} by risk:");
        for (int i = 0; i < n; i++)
        {
            var r = a.Assets[i];
            var drivers = r.Drivers.Count > 0 ? " — " + string.Join(", ", r.Drivers) : "";
            sb.AppendLine($"  {r.Score,5:0.0}  [{r.Grade}]  {r.Name}{drivers}");
        }
        return sb.ToString();
    }

    public static string Json(RiskAssessment a)
    {
        var projection = new
        {
            inventoryScore = a.InventoryScore,
            grade = a.Grade.ToString(),
            gradeLabel = RiskGrade.Label(a.Grade),
            timestamp = a.Timestamp,
            enrichmentPresent = a.EnrichmentPresent,
            bandCounts = a.BandCounts.ToDictionary(kv => kv.Key.ToString(), kv => kv.Value),
            assets = a.Assets.Select(r => new
            {
                bomRef = r.BomRef,
                name = r.Name,
                assetType = r.AssetType,
                score = r.Score,
                grade = r.Grade.ToString(),
                drivers = r.Drivers,
                factors = new
                {
                    usage = r.Factors.Usage,
                    role = r.Factors.Role,
                    validity = r.Factors.Validity,
                    keyStrength = r.Factors.KeyStrength,
                    exposure = r.Factors.Exposure,
                    readinessFactor = r.Factors.ReadinessFactor
                }
            })
        };
        return JsonSerializer.Serialize(projection, new JsonSerializerOptions { WriteIndented = true });
    }

    public static string Markdown(RiskAssessment a)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Post-Quantum Risk Report");
        sb.AppendLine();
        sb.AppendLine($"**Grade {a.Grade} ({RiskGrade.Label(a.Grade)})** — inventory score **{a.InventoryScore:0.0}/100**  ");
        sb.AppendLine($"Assessed {a.Timestamp} · {a.Assets.Count} assets");
        sb.AppendLine();
        if (!a.EnrichmentPresent) { sb.AppendLine($"> {EnrichmentNote}"); sb.AppendLine(); }

        sb.AppendLine("## Posture");
        sb.AppendLine();
        sb.AppendLine("| Grade | Label | Count |");
        sb.AppendLine("|---|---|---|");
        foreach (var g in new[] { 'F', 'D', 'C', 'B', 'A' })
            sb.AppendLine($"| {g} | {RiskGrade.Label(g)} | {a.BandCounts[g]} |");
        sb.AppendLine();

        sb.AppendLine("## Prioritized Remediation");
        sb.AppendLine();
        sb.AppendLine("| # | Score | Grade | Asset | Type | Top risk drivers |");
        sb.AppendLine("|---|---|---|---|---|---|");
        int n = Math.Min(a.Options.TopN, a.Assets.Count);
        for (int i = 0; i < n; i++)
        {
            var r = a.Assets[i];
            sb.AppendLine($"| {i + 1} | {r.Score:0.0} | {r.Grade} | {r.Name} | {r.AssetType} | {string.Join("; ", r.Drivers)} |");
        }
        sb.AppendLine();

        sb.AppendLine("## Methodology");
        sb.AppendLine();
        sb.AppendLine("Score = `100 × readinessFactor × exposure`, where exposure weights HNDL usage (0.40), asset role (0.25), validity window (0.20), and key strength (0.15). See the Certifactory README, \"Post-quantum risk scoring\", for the full ruleset.");
        if (a.Options.QuantumYear is not null && a.Options.DataShelfLife is not null)
        {
            sb.AppendLine();
            sb.AppendLine($"Mosca time-horizon applied: quantum-year {a.Options.QuantumYear}, data-shelf-life {a.Options.DataShelfLife} yr, migration {a.Options.MigrationYears} yr.");
        }
        return sb.ToString();
    }
}
