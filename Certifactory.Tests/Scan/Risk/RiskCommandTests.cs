// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.CommandLine;
using System.IO;
using FluentAssertions;
using Soverance.Certifactory.Commands;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan.Risk;

public class RiskCommandTests
{
    private static DiscoveredCertificate RootCa(string thumb) => new(
        SubjectName: "CN=root", IssuerName: "CN=root",
        NotBefore: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        NotAfter: new DateTime(2046, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        Sha256Thumbprint: thumb,
        SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
        SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",
        SubjectKeySizeBits: 4096,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "root.pfx",
        KeyUsages: new[] { false, false, true, false, true, true, true, false, false },
        IsCertificateAuthority: true);

    private static string WriteCbomToTemp()
    {
        var doc = CbomBuilder.Build(new[] { RootCa("rr") }, "H", "2026-01-01T00:00:00Z", "1.0.0");
        var path = Path.Combine(Path.GetTempPath(), $"cbom-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, CbomSerializer.Serialize(doc));
        return path;
    }

    [Fact]
    public void Risk_reads_input_file_and_prints_grade()
    {
        var path = WriteCbomToTemp();
        try
        {
            var cmd = RiskCommand.Build();
            var stdout = new StringWriter();
            var original = Console.Out;
            Console.SetOut(stdout);
            int exit;
            try { exit = cmd.Parse(new[] { "--input", path }).Invoke(); }
            finally { Console.SetOut(original); }

            exit.Should().Be(0);
            stdout.ToString().Should().Contain("Grade");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Fail_over_returns_nonzero_when_inventory_exceeds_threshold()
    {
        var path = WriteCbomToTemp(); // a vulnerable root CA => high score
        try
        {
            var cmd = RiskCommand.Build();
            var original = Console.Out;
            Console.SetOut(new StringWriter());
            int exit;
            try { exit = cmd.Parse(new[] { "--input", path, "--fail-over", "10" }).Invoke(); }
            finally { Console.SetOut(original); }

            exit.Should().Be(2);
        }
        finally { File.Delete(path); }
    }
}
