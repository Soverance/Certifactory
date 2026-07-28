// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using Soverance.Certifactory.Scan;

public static class ScanCommand
{
    public static Command Build()
    {
        var pathsArg = new Argument<string[]>("paths")
        {
            Description = "Files or directories to scan for certificates/keystores (.pem .crt .cer .der .pfx .p12).",
            Arity = ArgumentArity.ZeroOrMore
        };
        var outputOption = new Option<string?>("--output")
        {
            Description = "Write the CBOM to this file instead of stdout."
        };
        var pfxPwOption = new Option<string?>("--pfx-password-file")
        {
            Description = "Path to a file containing the password for encrypted PFX/P12 keystores."
        };
        var systemStoresOption = new Option<bool>("--system-stores")
        {
            Description = "Also scan OS certificate stores (see docs for platform coverage)."
        };
        var summaryOption = new Option<bool>("--summary")
        {
            Description = "Print a post-quantum readiness summary table to stderr."
        };

        var cmd = new Command("scan", "Scan local certificates/keystores and emit a CycloneDX 1.6 CBOM.");
        cmd.Add(pathsArg);
        cmd.Add(outputOption);
        cmd.Add(pfxPwOption);
        cmd.Add(systemStoresOption);
        cmd.Add(summaryOption);

        cmd.SetAction(parseResult =>
        {
            var opts = new ScanOptions(
                Paths: parseResult.GetValue(pathsArg) ?? System.Array.Empty<string>(),
                PfxPasswordFile: parseResult.GetValue(pfxPwOption),
                IncludeSystemStores: parseResult.GetValue(systemStoresOption),
                OutputPath: parseResult.GetValue(outputOption),
                Summary: parseResult.GetValue(summaryOption));

            var result = ScanRunner.Run(
                opts,
                hostName: Environment.MachineName,
                timestamp: DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                toolVersion: Common.GetAssemblyVersion());

            var json = CbomSerializer.Serialize(result.Document);
            if (opts.OutputPath is not null)
            {
                File.WriteAllText(opts.OutputPath, json);
                Console.Error.WriteLine("CBOM written to " + opts.OutputPath);
            }
            else
            {
                Console.WriteLine(json);
            }

            if (opts.Summary)
                Console.Error.Write(ScanSummary.Render(ScanSummary.Compute(result.Document)));

            foreach (var w in result.Warnings)
                Console.Error.WriteLine("warning: " + w);
        });

        return cmd;
    }
}
