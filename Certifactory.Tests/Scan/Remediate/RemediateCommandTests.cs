// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Certifactory.Tests.Scan.Remediate;

using Soverance.Certifactory.Commands;
using Soverance.Certifactory.Scan;
using Xunit;

public class RemediateCommandTests
{
    private static string WriteScannedCbom(string dir)
    {
        // Generate an owned RSA CA (has private key) → scan it → serialize CBOM.
        var signer = Soverance.Certifactory.Pq.SignerFactory.Create(
            Soverance.Certifactory.Pq.KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();
        var (_, pfx) = Soverance.Certifactory.Pq.CertificateBuilder.BuildCertificateWithPfx(
            new Soverance.Certifactory.Pq.CertificateSpec(
                Soverance.Certifactory.Pq.CertificatePurpose.RootCa, "SmokeCA", "pw", signer,
                ServerIp: null, EmailAddress: null, Issuer: null));
        var pwFile = Path.Combine(dir, "pw.txt"); File.WriteAllText(pwFile, "pw");
        var pfxPath = Path.Combine(dir, "ca.pfx"); File.WriteAllBytes(pfxPath, pfx);

        var result = ScanRunner.Run(
            new ScanOptions(new[] { pfxPath }, pwFile, IncludeSystemStores: false, OutputPath: null, Summary: false),
            "host", "2026-07-29T00:00:00Z", "0.0.0");
        var cbomPath = Path.Combine(dir, "cbom.json");
        File.WriteAllText(cbomPath, CbomSerializer.Serialize(result.Document));
        return cbomPath;
    }

    [Fact]
    public void Remediate_OnScannedOwnedCert_ExitsZeroAndEmitsReissueHint()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var cbom = WriteScannedCbom(dir);
            var sw = new StringWriter();
            var original = Console.Out;
            Console.SetOut(sw);
            int exit;
            try { exit = RemediateCommand.Build().Parse(new[] { "--input", cbom }).Invoke(); }
            finally { Console.SetOut(original); }

            var output = sw.ToString();
            Assert.Equal(0, exit);
            // The scanned cert carries its private key → controllable → a reissue command hint.
            // (Exact target algorithm is covered deterministically in RemediationPlannerTests.)
            Assert.Contains("--algorithm", output);
            Assert.Contains("certifactory", output);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Remediate_OnGarbageInput_ExitsOne()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var bad = Path.Combine(dir, "bad.json"); File.WriteAllText(bad, "not json");
            int exit = RemediateCommand.Build().Parse(new[] { "--input", bad }).Invoke();
            Assert.Equal(1, exit);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
