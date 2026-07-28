// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.IO;
using System.Linq;
using FluentAssertions;
using Org.BouncyCastle.Security;
using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan;

public class ScanRunnerTests
{
    private static string WritePemCert(string dir, string cn)
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, cn, "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));
        var bc = DotNetUtilities.FromX509Certificate(cert);
        var path = Path.Combine(dir, cn + ".pem");
        using var w = new StreamWriter(path);
        new Org.BouncyCastle.OpenSsl.PemWriter(w).WriteObject(bc);
        return path;
    }

    [Fact]
    public void Scans_a_directory_into_a_cbom_document()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        WritePemCert(dir, "runner-a");
        WritePemCert(dir, "runner-b");

        var opts = new ScanOptions(
            Paths: new[] { dir }, PfxPasswordFile: null, IncludeSystemStores: false,
            OutputPath: null, Summary: false);
        var result = ScanRunner.Run(opts, "HOST", "2026-07-27T00:00:00Z", "1.0.0");

        result.Document.Components.Count(c => c.CryptoProperties?.AssetType == "certificate").Should().Be(2);
        result.Document.SpecVersion.Should().Be("1.6");
    }

    [Fact]
    public void System_store_flag_scans_default_stores()
    {
        var opts = new ScanOptions(
            Paths: System.Array.Empty<string>(), PfxPasswordFile: null, IncludeSystemStores: true,
            OutputPath: null, Summary: false);

        // Store/dir contents differ by platform and host, so we only assert the
        // scan completes and produces a document, not a specific cert count.
        var result = ScanRunner.Run(opts, "HOST", "2026-07-27T00:00:00Z", "1.0.0");
        result.Document.Should().NotBeNull();
        result.Document.SpecVersion.Should().Be("1.6");
    }

    [Fact]
    public void Same_cert_in_two_file_formats_is_counted_once_with_warning()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "dup-formats", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));
        var bc = DotNetUtilities.FromX509Certificate(cert);
        // .pem
        using (var w = new StreamWriter(Path.Combine(dir, "c.pem")))
            new Org.BouncyCastle.OpenSsl.PemWriter(w).WriteObject(bc);
        // .der (raw DER of the same cert)
        File.WriteAllBytes(Path.Combine(dir, "c.der"), bc.GetEncoded());

        var opts = new ScanOptions(new[] { dir }, PfxPasswordFile: null, IncludeSystemStores: false, OutputPath: null, Summary: false);
        var result = ScanRunner.Run(opts, "HOST", "2026-07-27T00:00:00Z", "1.0.0");

        result.Document.Components.Count(c => c.CryptoProperties?.AssetType == "certificate").Should().Be(1);
        result.Document.Components.Select(c => c.BomRef).Should().OnlyHaveUniqueItems();
        result.Warnings.Should().Contain(w => w.Contains("counted once"));
    }
}
