// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Tls;

public static class TlsScanCommand
{
    public static Command Build()
    {
        var targetsArg = new Argument<string[]>("targets")
        { Description = "TLS endpoints as host:port (e.g. example.com:443).", Arity = ArgumentArity.ZeroOrMore };
        var targetsFile = new Option<string?>("--targets-file") { Description = "File with one host:port per line (# comments allowed)." };
        var output = new Option<string?>("--output") { Description = "Write the CBOM to this file instead of stdout." };
        var summary = new Option<bool>("--summary") { Description = "Print a post-quantum readiness summary to stderr." };
        var timeout = new Option<int>("--timeout") { Description = "Per-target handshake timeout in seconds (default 10)." };
        var concurrency = new Option<int>("--concurrency") { Description = "Max concurrent handshakes (default 8)." };

        var cmd = new Command("tls-scan", "Probe TLS endpoints and emit a CycloneDX 1.6 CBOM. Makes outbound connections only to the named targets — you must be authorized to scan them.");
        cmd.Add(targetsArg); cmd.Add(targetsFile); cmd.Add(output); cmd.Add(summary); cmd.Add(timeout); cmd.Add(concurrency);

        cmd.SetAction(parseResult =>
        {
            var opts = new TlsScanOptions(
                Targets: parseResult.GetValue(targetsArg) ?? System.Array.Empty<string>(),
                TargetsFile: parseResult.GetValue(targetsFile),
                OutputPath: parseResult.GetValue(output),
                Summary: parseResult.GetValue(summary),
                TimeoutSeconds: parseResult.GetValue(timeout),
                Concurrency: parseResult.GetValue(concurrency));

            var result = TlsScanRunner.Run(opts, Environment.MachineName,
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), Common.GetAssemblyVersion());

            var json = CbomSerializer.Serialize(result.Document);
            if (opts.OutputPath is not null) { File.WriteAllText(opts.OutputPath, json); Console.Error.WriteLine("CBOM written to " + opts.OutputPath); }
            else Console.WriteLine(json);

            if (opts.Summary)
                Console.Error.Write(ScanSummary.Render(ScanSummary.Compute(result.Document)));

            foreach (var w in result.Warnings) Console.Error.WriteLine("warning: " + w);
        });

        return cmd;
    }
}
