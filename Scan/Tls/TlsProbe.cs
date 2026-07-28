// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Tls;

using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using BcX509 = Org.BouncyCastle.X509.X509Certificate;

/// <summary>
/// Performs one BouncyCastle TLS handshake against a target and reports what was
/// negotiated. Ports the Task 1 spike's proven "Fallback B" (detection-only) approach:
/// BC 2.6.2 can advertise the X25519MLKEM768 hybrid group (codepoint 0x11EC) but cannot
/// complete a negotiation for it (no combiner/key-share logic exists for that codepoint).
/// When a server wants to negotiate it, BC observes the server's HelloRetryRequest
/// selecting 0x11EC and then aborts with TlsFatalAlert(illegal_parameter) trying to act
/// on a group it doesn't understand. That abort — captured group == 0x11EC — is treated
/// as the positive "PQ-ready" signal, not a probe failure; a second, classical-only
/// handshake is then run to fetch the served certificate chain (the HRR aborts before
/// Certificate is ever sent). Never throws: every failure path returns
/// <see cref="TlsEndpointResult"/> with Succeeded=false and FailureReason set.
/// </summary>
public static class TlsProbe
{
    // IANA codepoint for the X25519MLKEM768 hybrid group. Not defined by BC's
    // NamedGroup (BC 2.6.2 has no hybrid combiner), so both the offer and the
    // name mapping are hardcoded here.
    private const int HybridGroupId = 0x11EC;
    private const string HybridGroupName = "x25519mlkem768";

    public static TlsEndpointResult Probe(string host, int port, TimeSpan timeout)
    {
        try
        {
            var attempt1 = Attempt(host, port, timeout, offerHybridGroup: true, tls13Only: true);
            if (attempt1.Completed)
            {
                // BC cannot complete a negotiation for the hybrid group, so a
                // normally-completed handshake always negotiated a classical group.
                return BuildSuccess(host, port, attempt1.Client, kexGroupOverride: null);
            }

            // Not the happy path. Check for the one expected-and-positive failure
            // shape: the server selected the hybrid group via HelloRetryRequest and
            // BC then fatally aborted trying to act on a group it can't build a key
            // share for. This is the PQ-ready signal, not a probe error.
            if (attempt1.Client.HelloRetryRequestGroupId == HybridGroupId)
            {
                try
                {
                    var attempt2 = Attempt(host, port, timeout, offerHybridGroup: false, tls13Only: false);
                    if (attempt2.Completed)
                    {
                        return BuildSuccess(host, port, attempt2.Client, kexGroupOverride: HybridGroupName);
                    }

                    return Failure(host, port,
                        $"server selected the PQ-hybrid group ({HybridGroupName}) via HelloRetryRequest, " +
                        $"but the classical follow-up handshake to fetch the certificate chain failed: " +
                        $"{attempt2.Error?.Message}");
                }
                catch (Exception ex2)
                {
                    return Failure(host, port,
                        $"server selected the PQ-hybrid group ({HybridGroupName}) via HelloRetryRequest, " +
                        $"but the classical follow-up connection failed: {ex2.Message}");
                }
            }

            // No hybrid-HRR signal either — attempt #1 was TLS-1.3-only, so a
            // TLS-1.2-only (or otherwise non-1.3) server fails it even though it's
            // perfectly reachable. Run one more classical attempt at BC's default
            // versions (1.2 and 1.3, same helper/params as the classical follow-up
            // attempt above) before reporting the endpoint as unreachable.
            try
            {
                var classicalAttempt = Attempt(host, port, timeout, offerHybridGroup: false, tls13Only: false);
                if (classicalAttempt.Completed)
                {
                    return BuildSuccess(host, port, classicalAttempt.Client, kexGroupOverride: null);
                }

                return Failure(host, port,
                    classicalAttempt.Error?.Message ?? attempt1.Error?.Message ?? "TLS handshake failed.");
            }
            catch (Exception exClassical)
            {
                return Failure(host, port, exClassical.Message);
            }
        }
        catch (Exception ex)
        {
            // DNS resolution failures, connect-time exceptions, etc. surface here
            // (no ProbeClient instance exists yet to inspect for the HRR signal).
            return Failure(host, port, ex.Message);
        }
    }

    private static AttemptResult Attempt(
        string host, int port, TimeSpan timeout, bool offerHybridGroup, bool tls13Only)
    {
        // ConnectAsync(...).Wait(timeout) does not cancel the underlying connect
        // attempt on timeout, just stops waiting for it — dispose the TcpClient
        // regardless so the socket doesn't leak.
        using var tcp = new TcpClient();
        if (!tcp.ConnectAsync(host, port).Wait(timeout))
        {
            throw new TimeoutException($"Connection to {host}:{port} timed out after {timeout}.");
        }

        var crypto = new BcTlsCrypto(new SecureRandom());
        var client = new ProbeClient(crypto, host, offerHybridGroup, tls13Only);
        var protocol = new ProbeProtocol(tcp.GetStream(), client);
        try
        {
            protocol.Connect(client);
            protocol.Close();
            return new AttemptResult(true, client, null);
        }
        catch (Exception ex)
        {
            // Connect() throws on any handshake failure (alerts, timeouts inside the
            // handshake, etc.) — the caller decides whether this is the expected
            // HRR-positive signal or a genuine failure.
            return new AttemptResult(false, client, ex);
        }
    }

    private static TlsEndpointResult BuildSuccess(
        string host, int port, ProbeClient client, string? kexGroupOverride)
    {
        var certParser = new Org.BouncyCastle.X509.X509CertificateParser();
        var chain = client.CertDerChain
            .Select(der => certParser.ReadCertificate(der))
            .ToList();

        return new TlsEndpointResult(
            host,
            port,
            true,
            TlsVersionString(client.NegotiatedVersion),
            client.NegotiatedCipherSuite is int cs
                ? CipherSuiteNames.Table.GetValueOrDefault(cs, "UNKNOWN")
                : null,
            kexGroupOverride ?? GroupName(client.NegotiatedGroupId),
            chain,
            null);
    }

    private static TlsEndpointResult Failure(string host, int port, string reason) =>
        new(host, port, false, null, null, null, Array.Empty<BcX509>(), reason);

    // Task 3's protocol asset expects a bare version number ("1.3"/"1.2"), not BC's
    // human-readable "TLS 1.3".
    private static string? TlsVersionString(ProtocolVersion? version) =>
        version?.ToString().Replace("TLS ", "");

    // NamedGroup.GetName covers every classical/FFDHE/pure-ML-KEM group BC knows
    // about and returns "UNKNOWN" for anything else (including 0x11EC, which BC
    // doesn't define). 0x11EC only ever reaches here via a completed negotiation,
    // which cannot happen (BC can't complete it) — the override table exists mainly
    // for HelloRetryRequestGroupId, handled by the caller before this is consulted.
    private static string? GroupName(int? id) =>
        id is null ? null : id == HybridGroupId ? HybridGroupName : NamedGroup.GetName(id.Value);

    private sealed record AttemptResult(bool Completed, ProbeClient Client, Exception? Error);

    /// <summary>
    /// DefaultTlsClient subclass that advertises the hybrid group (when asked),
    /// pins SNI, and records what the server negotiated. The hybrid group itself
    /// (HelloRetryRequestGroupId) is recorded by <see cref="ProbeProtocol"/> — the
    /// generic <c>ProcessServerExtensions</c> hook never sees key_share (BC's
    /// protocol layer consumes/strips it before that callback fires).
    /// </summary>
    private sealed class ProbeClient : DefaultTlsClient
    {
        private readonly string _host;
        private readonly bool _offerHybridGroup;
        private readonly bool _tls13Only;

        public ProtocolVersion? NegotiatedVersion { get; private set; }
        public int? NegotiatedCipherSuite { get; private set; }
        public int? NegotiatedGroupId { get; set; }
        public int? HelloRetryRequestGroupId { get; set; }
        public List<byte[]> CertDerChain { get; } = new();

        public ProbeClient(TlsCrypto crypto, string host, bool offerHybridGroup, bool tls13Only)
            : base(crypto)
        {
            _host = host;
            _offerHybridGroup = offerHybridGroup;
            _tls13Only = tls13Only;
        }

        protected override IList<ServerName> GetSniServerNames() =>
            new List<ServerName> { new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(_host)) };

        public override ProtocolVersion[] GetProtocolVersions() =>
            _tls13Only ? new[] { ProtocolVersion.TLSv13 } : base.GetProtocolVersions();

        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles)
        {
            // NB: despite the base signature's parameter name, this is NOT a list of
            // default named groups — it's NamedGroupRole values (ECDH/DH/KEM role
            // markers) inferred from the offered cipher suites. Calling base.GetSupportedGroups
            // translates those roles into BC's actual crypto-capability-filtered default
            // group list (e.g. x25519/secp256r1/ffdhe*), which is what should be offered
            // instead of a hardcoded pair.
            var defaultGroups = base.GetSupportedGroups(namedGroupRoles);

            if (!_offerHybridGroup)
            {
                // Fresh copy per call — never hand back a shared mutable list to a
                // caller that might run probes concurrently (Task 5's runner).
                return new List<int>(defaultGroups);
            }

            // Offer the hybrid group ahead of BC's own defaults, rather than a
            // hardcoded classical pair, so servers supporting the hybrid group
            // alongside groups BC didn't hardcode here still negotiate normally.
            var groups = new List<int> { HybridGroupId };
            groups.AddRange(defaultGroups);
            return groups;
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);
            NegotiatedVersion = serverVersion;
        }

        public override void NotifySelectedCipherSuite(int selectedCipherSuite)
        {
            base.NotifySelectedCipherSuite(selectedCipherSuite);
            NegotiatedCipherSuite = selectedCipherSuite;
        }

        public override TlsAuthentication GetAuthentication() => new Auth(this);

        private sealed class Auth : TlsAuthentication
        {
            private readonly ProbeClient _owner;
            public Auth(ProbeClient owner) => _owner = owner;

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                foreach (var c in serverCertificate.Certificate.GetCertificateList())
                {
                    _owner.CertDerChain.Add(c.GetEncoded());
                }
            }

            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;
        }
    }

    /// <summary>
    /// Subclasses TlsClientProtocol (not just TlsClient) because the negotiated
    /// named group is not exposed anywhere else: SecurityParameters has no
    /// NamedGroup/SelectedGroup field, and by the time ProcessServerExtensions
    /// fires, BC has already consumed/stripped key_share to derive the handshake
    /// secret. ReceiveServerHelloMessage is the only point (for both a normal
    /// ServerHello and a HelloRetryRequest, which is wire-encoded as a ServerHello
    /// with IsHelloRetryRequest()==true) where the raw, unconsumed key_share
    /// extension is still present.
    /// </summary>
    private sealed class ProbeProtocol : TlsClientProtocol
    {
        private readonly ProbeClient _client;
        public ProbeProtocol(Stream stream, ProbeClient client) : base(stream) => _client = client;

        protected override ServerHello ReceiveServerHelloMessage(MemoryStream buf)
        {
            var sh = base.ReceiveServerHelloMessage(buf);
            RecordServerHelloExtensions(sh.Extensions, sh.IsHelloRetryRequest());
            return sh;
        }

        private void RecordServerHelloExtensions(IDictionary<int, byte[]>? extensions, bool isHelloRetryRequest)
        {
            if (extensions == null || !extensions.ContainsKey(ExtensionType.key_share))
            {
                return;
            }

            if (isHelloRetryRequest)
            {
                _client.HelloRetryRequestGroupId = TlsExtensionsUtilities.GetKeyShareHelloRetryRequest(extensions);
            }
            else
            {
                var entry = TlsExtensionsUtilities.GetKeyShareServerHello(extensions);
                _client.NegotiatedGroupId = entry.NamedGroup;
            }
        }
    }
}
