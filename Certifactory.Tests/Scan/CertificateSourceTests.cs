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

public class CertificateSourceTests
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
        var pw = new Org.BouncyCastle.OpenSsl.PemWriter(w);
        pw.WriteObject(bc);
        return path;
    }

    private static string WritePfx(string dir, string cn)
    {
        var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();
        var (_, pfxBytes) = CertificateBuilder.BuildCertificateWithPfx(new CertificateSpec(
            CertificatePurpose.RootCa, cn, "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));
        var path = Path.Combine(dir, cn + ".pfx");
        File.WriteAllBytes(path, pfxBytes);
        return path;
    }

    private static string WritePemBundle(string dir, string namePrefix)
    {
        var path = Path.Combine(dir, namePrefix + "-bundle.pem");
        using (var w = new StreamWriter(path))
        {
            var pw = new Org.BouncyCastle.OpenSsl.PemWriter(w);
            foreach (var suffix in new[] { "a", "b" })
            {
                var cn = namePrefix + "-" + suffix;
                var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
                signer.GenerateKeyPair();
                var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
                    CertificatePurpose.RootCa, cn, "Pass", signer,
                    ServerIp: null, EmailAddress: null, Issuer: null));
                pw.WriteObject(DotNetUtilities.FromX509Certificate(cert));
            }
        }
        return path;
    }

    [Fact]
    public void Loads_pem_certificate()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var path = WritePemCert(dir, "pem-load-test");
        var result = CertificateSource.LoadFromPath(path, null);

        result.Certificates.Should().ContainSingle();
        result.Certificates[0].Cert.SubjectDN.ToString().Should().Contain("pem-load-test");
        result.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Loads_pfx_certificate_with_password()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var path = WritePfx(dir, "pfx-load-test");
        var result = CertificateSource.LoadFromPath(path, "Pass");
        result.Certificates.Should().ContainSingle();
        result.Certificates[0].Cert.SubjectDN.ToString().Should().Contain("pfx-load-test");
        result.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Encrypted_pfx_without_password_warns_and_skips()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var path = WritePfx(dir, "pfx-nopw-test");
        var result = CertificateSource.LoadFromPath(path, null);
        result.Certificates.Should().BeEmpty();
        result.Warnings.Should().ContainSingle().Which.Should().Contain("pfx-nopw-test");
    }

    [Fact]
    public void Directory_walk_aggregates_multiple_files()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        WritePemCert(dir, "walk-a");
        WritePemCert(dir, "walk-b");
        var result = CertificateSource.LoadFromDirectory(dir, null);
        result.Certificates.Should().HaveCount(2);
    }

    [Fact]
    public void Pfx_with_wrong_password_warns_and_skips()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var path = WritePfx(dir, "pfx-wrongpw-test");
        var result = CertificateSource.LoadFromPath(path, "DefinitelyWrong");
        result.Certificates.Should().BeEmpty();
        result.Warnings.Should().ContainSingle();
    }

    [Fact]
    public void Pem_bundle_with_two_certificates_loads_both()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var path = WritePemBundle(dir, "bundle");
        var result = CertificateSource.LoadFromPath(path, null);
        result.Certificates.Should().HaveCount(2);
    }
}
