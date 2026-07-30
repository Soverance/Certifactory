// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Certifactory.Tests.Scan.Remediate;

using Soverance.Certifactory.Scan.Remediate;
using Soverance.Certifactory.Scan.Risk;
using Xunit;

public class RemediationRendererTests
{
    private static RemediationPlan Sample(bool custody = true)
    {
        var controllable = new RemediationItem(
            "cert:1", "CN=MyCA", 86.5, 'F', RemediationAction.ReissuePqc, TargetAlgorithm.MlDsa65,
            "certifactory ca \"CN=MyCA\" <password> ./out --algorithm ml-dsa-65");
        var vendor = new RemediationItem(
            "cert:2", "CN=DigiCert", 64.5, 'D', RemediationAction.MonitorVendor, TargetAlgorithm.None, null);
        return new RemediationPlan(
            TotalAssets: 2, ControllableCount: 1, VendorDependentCount: 1,
            ManualReviewCount: 0, AlreadySafeCount: 0,
            Controllable: new[] { controllable }, All: new[] { controllable, vendor },
            Options: new RiskOptions(), Timestamp: "2026-07-29T00:00:00Z", CustodyPresent: custody);
    }

    [Fact]
    public void Table_ShowsHeadlineAndCommandHint()
    {
        var t = RemediationRenderer.Table(Sample());
        Assert.Contains("1 controllable", t);
        Assert.Contains("ml-dsa-65", t);
        Assert.Contains("--algorithm ml-dsa-65", t);   // command hint present
    }

    [Fact]
    public void Table_WithoutCustody_PrintsNote()
    {
        var t = RemediationRenderer.Table(Sample(custody: false));
        Assert.Contains("custody", t, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Json_IsMachineReadable()
    {
        var j = RemediationRenderer.Json(Sample());
        using var doc = System.Text.Json.JsonDocument.Parse(j);
        Assert.Equal(1, doc.RootElement.GetProperty("controllableCount").GetInt32());
        Assert.Equal("ReissuePqc",
            doc.RootElement.GetProperty("assets")[0].GetProperty("action").GetString());
    }

    [Fact]
    public void Markdown_HasActionTable()
    {
        var m = RemediationRenderer.Markdown(Sample());
        Assert.Contains("# Post-Quantum Remediation Plan", m);
        Assert.Contains("ml-dsa-65", m);
    }
}
