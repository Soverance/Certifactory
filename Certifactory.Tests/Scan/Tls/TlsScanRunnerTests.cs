// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using FluentAssertions;
using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan;
using Soverance.Certifactory.Scan.Tls;
using Xunit;

namespace Certifactory.Tests.Scan.Tls;

public class TlsScanRunnerTests
{
    [Fact]
    public void Scans_a_live_target_and_warns_on_a_dead_one()
    {
        var (_, pfx) = CertificateBuilder.BuildCertificateWithPfx(new CertificateSpec(
            CertificatePurpose.Server, "localhost", "Pass", Rsa(),
            ServerIp: "127.0.0.1", EmailAddress: null, Issuer: null));
        using var serverCert = new X509Certificate2(pfx, "Pass",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            using var ssl = new SslStream(c.GetStream(), false);
            await ssl.AuthenticateAsServerAsync(serverCert);
        });

        try
        {
            var opts = new TlsScanOptions(
                Targets: new[] { $"127.0.0.1:{port}", "127.0.0.1:1" },
                TargetsFile: null, OutputPath: null, Summary: false,
                TimeoutSeconds: 5, Concurrency: 4);
            var result = TlsScanRunner.Run(opts, "SCANHOST", "2026-07-28T00:00:00Z", "1.0.0");

            result.Document.Components.Count(c => c.CryptoProperties?.AssetType == "protocol").Should().Be(1);
            result.Warnings.Should().Contain(w => w.Contains("127.0.0.1:1"));
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public void Duplicate_targets_dedupe_to_one_protocol_component_and_summary_does_not_throw()
    {
        var (_, pfx) = CertificateBuilder.BuildCertificateWithPfx(new CertificateSpec(
            CertificatePurpose.Server, "localhost", "Pass", Rsa(),
            ServerIp: "127.0.0.1", EmailAddress: null, Issuer: null));
        using var serverCert = new X509Certificate2(pfx, "Pass",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        // Runner dedupes (host, port) before probing, so the duplicate target below
        // should still result in exactly one TCP connection/handshake.
        var serverTask = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            using var ssl = new SslStream(c.GetStream(), false);
            await ssl.AuthenticateAsServerAsync(serverCert);
        });

        try
        {
            var target = $"127.0.0.1:{port}";
            var opts = new TlsScanOptions(
                Targets: new[] { target, target },
                TargetsFile: null, OutputPath: null, Summary: false,
                TimeoutSeconds: 5, Concurrency: 4);
            var result = TlsScanRunner.Run(opts, "SCANHOST", "2026-07-28T00:00:00Z", "1.0.0");

            result.Document.Components.Count(c => c.CryptoProperties?.AssetType == "protocol").Should().Be(1);
            result.Document.Components.Select(c => c.BomRef).Should().OnlyHaveUniqueItems();

            Action act = () => ScanSummary.Compute(result.Document);
            act.Should().NotThrow();
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public void Malformed_target_is_warned_not_thrown()
    {
        var opts = new TlsScanOptions(new[] { "not-a-target" }, null, null, false, 2, 2);
        var result = TlsScanRunner.Run(opts, "H", "2026-07-28T00:00:00Z", "1.0.0");
        result.Warnings.Should().Contain(w => w.Contains("not-a-target"));
    }

    private static IPqSigner Rsa() { var s = SignerFactory.Create(KnownAlgorithms.Rsa4096); s.GenerateKeyPair(); return s; }
}
