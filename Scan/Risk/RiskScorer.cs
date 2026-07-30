// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Risk;

using System.Globalization;
using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Tls;

/// <summary>
/// Pure post-quantum risk scorer: score = 100 * readinessFactor * exposure,
/// where exposure is a weighted average of usage/role/validity/key-strength.
/// Reads the enriched CBOM (cert role + key usage properties) via CbomGraph;
/// degrades conservatively when those properties are absent. No I/O, no clock.
/// See docs/superpowers/specs/2026-07-28-risk-scoring-design.md and README.
/// </summary>
public static class RiskScorer
{
    public static RiskAssessment Score(CbomDocument doc, RiskOptions options, DateTime now)
    {
        var graph = new CbomGraph(doc);
        var assets = new List<AssetRisk>();

        foreach (var comp in doc.Components)
        {
            switch (comp.CryptoProperties?.AssetType)
            {
                case "certificate": assets.Add(ScoreCertificate(comp, graph, options, now)); break;
                case "protocol":    assets.Add(ScoreProtocol(comp, graph, options, now)); break;
            }
        }

        var sorted = assets.OrderByDescending(a => a.Score).ThenBy(a => a.BomRef).ToList();
        double inventory = sorted.Count == 0 ? 0 : sorted.Average(a => a.Score);

        var bandCounts = new Dictionary<char, int> { ['A'] = 0, ['B'] = 0, ['C'] = 0, ['D'] = 0, ['F'] = 0 };
        foreach (var a in sorted) bandCounts[a.Grade]++;

        bool enrichmentPresent = doc.Components.Any(c =>
            c.Properties?.Any(p => p.Name == "certifactory:certificate:role") == true);

        return new RiskAssessment(
            InventoryScore: Math.Round(inventory, 1),
            Grade: RiskGrade.For(inventory),
            Assets: sorted,
            BandCounts: bandCounts,
            Options: options,
            Timestamp: now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            EnrichmentPresent: enrichmentPresent);
    }

    private static AssetRisk ScoreCertificate(Component comp, CbomGraph graph, RiskOptions options, DateTime now)
    {
        var algs = graph.AlgorithmsFor(comp.BomRef);
        bool hasVuln = algs.Any(a => a.Readiness == PqReadiness.Vulnerable);
        bool hasSafe = algs.Any(a => a.Readiness == PqReadiness.QuantumSafe);
        var readiness =
            hasVuln && hasSafe ? RiskReadiness.Hybrid :
            hasSafe            ? RiskReadiness.QuantumSafe :
            hasVuln            ? RiskReadiness.Vulnerable :
                                 RiskReadiness.Unknown;

        string role = PropertyValue(comp, "certifactory:certificate:role") ?? "leaf";

        string usage = "unknown";
        int? keySize = null;
        var keyRef = comp.CryptoProperties?.CertificateProperties?.SubjectPublicKeyRef;
        if (keyRef is not null && graph.ComponentFor(keyRef) is { } keyComp)
        {
            usage = PropertyValue(keyComp, "certifactory:key:usage") ?? "unknown";
            keySize = keyComp.CryptoProperties?.RelatedCryptoMaterialProperties?.Size;
        }

        double validityF = ValidityFactor(
            comp.CryptoProperties?.CertificateProperties?.NotValidAfter, options, now);

        return Build(comp.BomRef, comp.Name, "certificate", readiness, usage, role, validityF, keySize);
    }

    private static AssetRisk ScoreProtocol(Component comp, CbomGraph graph, RiskOptions options, DateTime now)
    {
        var kex = graph.KexFor(comp.BomRef);
        var readiness =
            kex.IsHybrid                              ? RiskReadiness.Hybrid :
            kex.Readiness == PqReadiness.QuantumSafe  ? RiskReadiness.QuantumSafe :
            kex.Readiness == PqReadiness.Vulnerable   ? RiskReadiness.Vulnerable :
                                                        RiskReadiness.Unknown;

        // KEX is always key-establishment (HNDL); a live endpoint has max validity exposure.
        double validityF = (options.QuantumYear is not null && options.DataShelfLife is not null)
            ? MoscaValidityFactor(options, now)
            : 1.0;

        return Build(comp.BomRef, comp.Name, "protocol", readiness, "key-establishment", "tls-endpoint", validityF, null);
    }

    private static AssetRisk Build(
        string bomRef, string name, string assetType,
        RiskReadiness readiness, string usage, string role, double validityF, int? keySize)
    {
        double usageF = UsageFactor(usage);
        double roleF = RoleFactor(role);
        double strengthF = StrengthFactor(keySize);
        double exposure = 0.40 * usageF + 0.25 * roleF + 0.20 * validityF + 0.15 * strengthF;
        double readinessF = ReadinessFactor(readiness);
        double score = Math.Clamp(100.0 * readinessF * exposure, 0, 100);

        var factors = new FactorBreakdown(usageF, roleF, validityF, strengthF, exposure, readinessF);
        return new AssetRisk(bomRef, name, assetType, Math.Round(score, 1), RiskGrade.For(score),
            factors, Drivers(readiness, usage, role, validityF));
    }

    private static double ReadinessFactor(RiskReadiness r) => r switch
    {
        RiskReadiness.Vulnerable  => 1.0,
        RiskReadiness.Unknown     => 0.85,
        RiskReadiness.Hybrid      => 0.35,
        RiskReadiness.QuantumSafe => 0.0,
        _                         => 1.0
    };

    private static double UsageFactor(string usage) => usage == "signature" ? 0.3 : 1.0;

    private static double RoleFactor(string role) => role switch
    {
        "root-ca"         => 1.0,
        "intermediate-ca" => 0.7,
        "tls-endpoint"    => 0.5,
        _                 => 0.3   // leaf / unknown
    };

    private static double StrengthFactor(int? size) => size switch
    {
        null     => 0.5,
        < 2048   => 1.0,
        < 4096   => 0.5,
        _        => 0.2
    };

    private static double ValidityFactor(string? notAfterIso, RiskOptions options, DateTime now)
    {
        if (options.QuantumYear is not null && options.DataShelfLife is not null)
            return MoscaValidityFactor(options, now);

        if (notAfterIso is null ||
            !DateTime.TryParse(notAfterIso, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var notAfter))
            return 0.4; // unknown validity => mid exposure

        double years = (notAfter - now).TotalDays / 365.25;
        return years switch
        {
            > 10 => 1.0,
            > 5  => 0.7,
            > 1  => 0.4,
            _    => 0.15
        };
    }

    private static double MoscaValidityFactor(RiskOptions options, DateTime now)
    {
        double nowYears = now.Year + (now.DayOfYear - 1) / 365.25;
        double yearsToQ = options.QuantumYear!.Value - nowYears;
        double horizon = options.DataShelfLife!.Value + options.MigrationYears;
        if (yearsToQ <= 0 || horizon >= yearsToQ) return 1.0;
        return Math.Clamp(horizon / yearsToQ, 0.15, 1.0);
    }

    private static IReadOnlyList<string> Drivers(RiskReadiness r, string usage, string role, double validityF)
    {
        var d = new List<string>();
        switch (r)
        {
            case RiskReadiness.Vulnerable: d.Add("quantum-vulnerable algorithm"); break;
            case RiskReadiness.Unknown:    d.Add("unrecognized algorithm"); break;
            case RiskReadiness.Hybrid:     d.Add("hybrid (transitional)"); break;
        }
        if (r != RiskReadiness.QuantumSafe && usage is "key-establishment" or "both" or "unknown")
            d.Add("harvest-now-decrypt-later exposure");
        if (role == "root-ca") d.Add("root CA blast radius");
        else if (role == "intermediate-ca") d.Add("intermediate CA blast radius");
        if (r != RiskReadiness.QuantumSafe && validityF >= 0.7) d.Add("long remaining validity");
        return d.Take(2).ToList();
    }

    private static string? PropertyValue(Component comp, string name)
        => comp.Properties?.FirstOrDefault(p => p.Name == name)?.Value;
}
