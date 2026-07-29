// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan.Tls;
using Xunit;

namespace Certifactory.Tests.Scan.Tls;

public class TlsProbeTests
{
    [Fact]
    public void Probes_a_local_tls_server_and_captures_version_cipher_and_cert()
    {
        // Spin a minimal TLS 1.2/1.3 server on 127.0.0.1 with a self-signed cert.
        var (cert, pfxBytes) = CertificateBuilder.BuildCertificateWithPfx(new CertificateSpec(
            CertificatePurpose.Server, "localhost", "Pass", MakeRsaSigner(),
            ServerIp: "127.0.0.1", EmailAddress: null, Issuer: null));
        using var serverCert = new X509Certificate2(pfxBytes, "Pass",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var ssl = new SslStream(client.GetStream(), false);
            await ssl.AuthenticateAsServerAsync(serverCert);
        });

        try
        {
            var result = TlsProbe.Probe("127.0.0.1", port, TimeSpan.FromSeconds(10));

            result.Succeeded.Should().BeTrue(result.FailureReason);
            result.TlsVersion.Should().MatchRegex("1\\.[23]");
            result.CipherSuite.Should().NotBeNullOrEmpty();
            result.Chain.Should().NotBeEmpty();
            result.Chain[0].SubjectDN.ToString().Should().Contain("localhost");
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void Tls12_only_server_is_reported_as_reachable_via_classical_fallback()
    {
        // Attempt #1 in TlsProbe is TLS-1.3-only, so a live TLS-1.2-only server
        // (no 1.3, no hybrid HelloRetryRequest) must fall through to the classical
        // fallback attempt and still be reported as reachable (B1 regression test).
        var (cert, pfxBytes) = CertificateBuilder.BuildCertificateWithPfx(new CertificateSpec(
            CertificatePurpose.Server, "localhost", "Pass", MakeRsaSigner(),
            ServerIp: "127.0.0.1", EmailAddress: null, Issuer: null));
        using var serverCert = new X509Certificate2(pfxBytes, "Pass",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        // TlsProbe.Probe makes up to two TCP connections here: attempt #1 (TLS-1.3-
        // only ClientHello) is expected to fail the version negotiation against this
        // TLS-1.2-only server, then the classical fallback attempt reconnects and
        // succeeds. Accept twice, swallowing the first connection's expected failure.
        var serverTask = Task.Run(async () =>
        {
            for (int i = 0; i < 2; i++)
            {
                try
                {
                    using var client = await listener.AcceptTcpClientAsync();
                    using var ssl = new SslStream(client.GetStream(), false);
                    var sslOptions = new SslServerAuthenticationOptions
                    {
                        ServerCertificate = serverCert,
                        EnabledSslProtocols = SslProtocols.Tls12
                    };
                    await ssl.AuthenticateAsServerAsync(sslOptions, CancellationToken.None);
                }
                catch
                {
                    // Expected for the TLS-1.3-only first attempt; keep looping so
                    // the classical fallback connection still gets served.
                }
            }
        });

        try
        {
            var result = TlsProbe.Probe("127.0.0.1", port, TimeSpan.FromSeconds(10));

            result.Succeeded.Should().BeTrue(result.FailureReason);
            result.TlsVersion.Should().Contain("1.2");
            result.Chain.Should().NotBeEmpty();
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void Nonexistent_port_fails_gracefully_without_throwing()
    {
        var result = TlsProbe.Probe("127.0.0.1", 1, TimeSpan.FromSeconds(2));
        result.Succeeded.Should().BeFalse();
        result.FailureReason.Should().NotBeNullOrEmpty();
    }

    private static IPqSigner MakeRsaSigner()
    {
        var s = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        s.GenerateKeyPair();
        return s;
    }
}
