// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Remediate;

using System.Globalization;
using Soverance.Certifactory.Scan.Risk;

/// <summary>
/// Turns a scored CBOM into an actionable remediation playbook. Reuses RiskScorer
/// for scores/ordering (never modifies it), then joins each asset with its custody,
/// role, usage, and validity from the CBOM to choose an action + target algorithm.
/// Pure: no I/O, clock supplied by the caller.
/// </summary>
public static class RemediationPlanner
{
    public static RemediationPlan Plan(CbomDocument doc, RiskOptions options, DateTime now)
    {
        var assessment = RiskScorer.Score(doc, options, now);
        var graph = new CbomGraph(doc);

        bool custodyPresent = doc.Components.Any(c =>
            c.Properties?.Any(p => p.Name == "certifactory:certificate:custody") == true);

        var items = assessment.Assets.Select(a => PlanOne(a, graph)).ToList();

        var controllable = items
            .Where(i => i.Action == RemediationAction.ReissuePqc)
            .OrderByDescending(i => i.Score).ThenBy(i => i.BomRef).ToList();

        return new RemediationPlan(
            TotalAssets: items.Count,
            ControllableCount: controllable.Count,
            VendorDependentCount: items.Count(i => i.Action == RemediationAction.MonitorVendor),
            ManualReviewCount: items.Count(i => i.Action == RemediationAction.ManualReview),
            AlreadySafeCount: items.Count(i => i.Action is RemediationAction.AlreadyHybrid or RemediationAction.None),
            Controllable: controllable,
            All: items,
            Options: options,
            Timestamp: assessment.Timestamp,
            CustodyPresent: custodyPresent);
    }

    private static RemediationItem PlanOne(AssetRisk asset, CbomGraph graph)
    {
        double rf = asset.Factors.ReadinessFactor;   // 1.0 vuln, 0.85 unknown, 0.35 hybrid, 0.0 safe
        if (rf <= 0.0)  return Item(asset, RemediationAction.None, TargetAlgorithm.None, null);
        if (rf < 0.85)  return Item(asset, RemediationAction.AlreadyHybrid, TargetAlgorithm.None, null);

        var comp = graph.ComponentFor(asset.BomRef);
        string? custody = Prop(comp, "certifactory:certificate:custody");
        if (custody is null)         return Item(asset, RemediationAction.ManualReview, TargetAlgorithm.None, null);
        if (custody != "owned-key")  return Item(asset, RemediationAction.MonitorVendor, TargetAlgorithm.None, null);

        string role = Prop(comp, "certifactory:certificate:role") ?? "leaf";
        string usage = UsageFor(comp, graph);
        double span = ValiditySpanYears(comp);
        var target = AlgorithmPolicy.Recommend(role, usage, span);
        string hint = BuildHint(AlgorithmPolicy.CommandName(role), ExtractCommonName(asset.Name), target);
        return Item(asset, RemediationAction.ReissuePqc, target, hint);
    }

    /// <summary>
    /// Extracts the value of the first CN= RDN from a subject DN (e.g.
    /// "CN=SOV-Lab, O=Foo" -> "SOV-Lab"), stopping at the next unescaped comma.
    /// Falls back to the original string if no CN= is present. Simple and
    /// defensive, not a full RFC 4514 DN parser.
    /// </summary>
    private static string ExtractCommonName(string subjectDn)
    {
        const string marker = "CN=";
        int idx = subjectDn.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0) return subjectDn;

        int start = idx + marker.Length;
        int i = start;
        while (i < subjectDn.Length)
        {
            if (subjectDn[i] == '\\' && i + 1 < subjectDn.Length) { i += 2; continue; }
            if (subjectDn[i] == ',') break;
            i++;
        }

        return subjectDn[start..i].Trim();
    }

    /// <summary>
    /// Builds the copy-pasteable command hint for the recommended reissue,
    /// matching each command's real positional-argument shape (see
    /// Commands/CaCommand.cs and Commands/ServerCommand.cs).
    /// </summary>
    private static string BuildHint(string commandName, string cn, TargetAlgorithm target)
    {
        string algo = target.ToAlgorithmId();
        return commandName switch
        {
            "ca" => $"certifactory ca \"{cn}\" <password> ./out --algorithm {algo}",
            _    => $"certifactory server \"{cn}\" <password> <server-ip> <root-ca.pfx> <root-ca-pw> ./out --algorithm {algo}",
        };
    }

    private static RemediationItem Item(AssetRisk a, RemediationAction action, TargetAlgorithm t, string? hint)
        => new(a.BomRef, a.Name, a.Score, a.Grade, action, t, hint);

    private static string? Prop(Component? c, string name)
        => c?.Properties?.FirstOrDefault(p => p.Name == name)?.Value;

    private static string UsageFor(Component? comp, CbomGraph graph)
    {
        var keyRef = comp?.CryptoProperties?.CertificateProperties?.SubjectPublicKeyRef;
        if (keyRef is not null && graph.ComponentFor(keyRef) is { } keyComp)
            return Prop(keyComp, "certifactory:key:usage") ?? "unknown";
        return "unknown";
    }

    private static double ValiditySpanYears(Component? comp)
    {
        var cp = comp?.CryptoProperties?.CertificateProperties;
        if (cp is null) return 0;
        const DateTimeStyles style = DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal;
        if (DateTime.TryParse(cp.NotValidBefore, CultureInfo.InvariantCulture, style, out var nb) &&
            DateTime.TryParse(cp.NotValidAfter,  CultureInfo.InvariantCulture, style, out var na))
            return (na - nb).TotalDays / 365.25;
        return 0;
    }
}
