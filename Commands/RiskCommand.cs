// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Risk;

public static class RiskCommand
{
    public static Command Build()
    {
        var inputOption = new Option<string?>("--input")
        {
            Description = "Read the CBOM from this file instead of stdin."
        };
        var formatOption = new Option<string>("--format")
        {
            Description = "Console output format: table (default) or json.",
            DefaultValueFactory = _ => "table"
        };
        var reportOption = new Option<string?>("--report")
        {
            Description = "Also write a shareable Markdown risk report to this path."
        };
        var topOption = new Option<int>("--top")
        {
            Description = "Limit the prioritized list to the N highest-risk assets.",
            DefaultValueFactory = _ => 20
        };
        var quantumYearOption = new Option<int?>("--quantum-year")
        {
            Description = "Mosca override: estimated year a cryptographically-relevant quantum computer arrives."
        };
        var shelfLifeOption = new Option<double?>("--data-shelf-life")
        {
            Description = "Mosca override: years the protected data must remain confidential."
        };
        var migrationOption = new Option<double>("--migration-time")
        {
            Description = "Mosca override: years required to complete PQ migration (default 1).",
            DefaultValueFactory = _ => 1.0
        };
        var failOverOption = new Option<double?>("--fail-over")
        {
            Description = "Exit with code 2 if the inventory risk score exceeds this value (CI gate)."
        };

        var cmd = new Command("risk", "Score a CycloneDX CBOM for post-quantum risk (per-asset scores + inventory grade).");
        cmd.Add(inputOption);
        cmd.Add(formatOption);
        cmd.Add(reportOption);
        cmd.Add(topOption);
        cmd.Add(quantumYearOption);
        cmd.Add(shelfLifeOption);
        cmd.Add(migrationOption);
        cmd.Add(failOverOption);

        cmd.SetAction(parseResult =>
        {
            var inputPath = parseResult.GetValue(inputOption);
            string json = inputPath is not null
                ? File.ReadAllText(inputPath)
                : Console.In.ReadToEnd();

            var doc = CbomSerializer.Deserialize(json);
            if (doc is null)
            {
                Console.Error.WriteLine("Error: could not parse CBOM input.");
                return 1;
            }

            var options = new RiskOptions(
                TopN: parseResult.GetValue(topOption),
                QuantumYear: parseResult.GetValue(quantumYearOption),
                DataShelfLife: parseResult.GetValue(shelfLifeOption),
                MigrationYears: parseResult.GetValue(migrationOption),
                FailOver: parseResult.GetValue(failOverOption));

            var assessment = RiskScorer.Score(doc, options, DateTime.UtcNow);

            var format = parseResult.GetValue(formatOption);
            Console.Write(format == "json"
                ? RiskReportRenderer.Json(assessment)
                : RiskReportRenderer.Table(assessment));
            Console.WriteLine();

            var reportPath = parseResult.GetValue(reportOption);
            if (reportPath is not null)
            {
                File.WriteAllText(reportPath, RiskReportRenderer.Markdown(assessment));
                Console.Error.WriteLine("Risk report written to " + reportPath);
            }

            if (options.FailOver is not null && assessment.InventoryScore > options.FailOver.Value)
            {
                Console.Error.WriteLine(
                    $"Risk gate failed: inventory score {assessment.InventoryScore:0.0} > {options.FailOver.Value:0.0}");
                return 2;
            }

            return 0;
        });

        return cmd;
    }
}
