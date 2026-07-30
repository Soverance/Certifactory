// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Collections.Generic;
using System.Text.Json;
using FluentAssertions;
using Soverance.Certifactory.Scan.Risk;
using Xunit;

namespace Certifactory.Tests.Scan.Risk;

public class RiskReportRendererTests
{
    private static RiskAssessment Sample()
    {
        var worst = new AssetRisk("cert:rr", "CN=root", "certificate", 88.0, 'F',
            new FactorBreakdown(1.0, 1.0, 1.0, 0.2, 0.88, 1.0),
            new[] { "quantum-vulnerable algorithm", "root CA blast radius" });
        var mild = new AssetRisk("cert:ll", "CN=leaf", "certificate", 25.5, 'B',
            new FactorBreakdown(0.3, 0.3, 0.15, 0.2, 0.255, 1.0),
            new[] { "quantum-vulnerable algorithm" });
        return new RiskAssessment(
            InventoryScore: 56.8, Grade: 'C',
            Assets: new[] { worst, mild },
            BandCounts: new Dictionary<char, int> { ['A'] = 0, ['B'] = 1, ['C'] = 0, ['D'] = 0, ['F'] = 1 },
            Options: new RiskOptions(),
            Timestamp: "2026-01-01T00:00:00Z",
            EnrichmentPresent: true);
    }

    [Fact]
    public void Table_lists_worst_first_and_shows_grade()
    {
        var text = RiskReportRenderer.Table(Sample());
        text.Should().Contain("Grade C");
        text.IndexOf("CN=root").Should().BeLessThan(text.IndexOf("CN=leaf")); // worst first
        text.Should().Contain("root CA blast radius");
    }

    [Fact]
    public void Json_is_parseable_and_carries_inventory_and_assets()
    {
        var json = RiskReportRenderer.Json(Sample());
        using var doc = JsonDocument.Parse(json);
        doc.RootElement.GetProperty("inventoryScore").GetDouble().Should().Be(56.8);
        doc.RootElement.GetProperty("grade").GetString().Should().Be("C");
        doc.RootElement.GetProperty("assets").GetArrayLength().Should().Be(2);
        doc.RootElement.GetProperty("assets")[0].GetProperty("bomRef").GetString().Should().Be("cert:rr");
    }

    [Fact]
    public void Markdown_contains_the_four_sections()
    {
        var md = RiskReportRenderer.Markdown(Sample());
        md.Should().Contain("# Post-Quantum Risk Report");
        md.Should().Contain("## Posture");
        md.Should().Contain("## Prioritized Remediation");
        md.Should().Contain("## Methodology");
        md.Should().Contain("Grade C");
    }

    [Fact]
    public void Markdown_notes_missing_enrichment()
    {
        var a = Sample() with { EnrichmentPresent = false };
        var md = RiskReportRenderer.Markdown(a);
        md.Should().Contain("enrichment");
    }
}
