// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Pq;

using System.Collections.Immutable;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

public sealed class RsaSigner : IPqSigner
{
    private const string AlreadyInitializedMessage =
        "GenerateKeyPair/LoadKeyPair must be called exactly once per instance.";

    private readonly SecureRandom _random = new();
    private AsymmetricCipherKeyPair? _keyPair;

    public string AlgorithmId => KnownAlgorithms.Rsa4096;

    public AsymmetricCipherKeyPair KeyPair
        => _keyPair ?? throw new InvalidOperationException(
            "Call GenerateKeyPair or LoadKeyPair before accessing KeyPair.");

    public void GenerateKeyPair()
    {
        if (_keyPair is not null)
            throw new InvalidOperationException(AlreadyInitializedMessage);

        var gen = new RsaKeyPairGenerator();
        gen.Init(new RsaKeyGenerationParameters(
            BigInteger.ValueOf(0x10001), _random, 4096, 100));
        _keyPair = gen.GenerateKeyPair();
    }

    public void LoadKeyPair(AsymmetricCipherKeyPair keyPair)
    {
        if (_keyPair is not null)
            throw new InvalidOperationException(AlreadyInitializedMessage);

        _keyPair = keyPair;
    }

    public ISignatureFactory CreateSignatureFactory()
        => new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private, _random);
}

public sealed class MlDsaSigner : IPqSigner
{
    private const string AlreadyInitializedMessage =
        "GenerateKeyPair/LoadKeyPair must be called exactly once per instance.";

    private readonly SecureRandom _random = new();
    private AsymmetricCipherKeyPair? _keyPair;

    public string AlgorithmId => KnownAlgorithms.MlDsa65;

    public AsymmetricCipherKeyPair KeyPair
        => _keyPair ?? throw new InvalidOperationException(
            "Call GenerateKeyPair or LoadKeyPair before accessing KeyPair.");

    public void GenerateKeyPair()
    {
        if (_keyPair is not null)
            throw new InvalidOperationException(AlreadyInitializedMessage);

        var gen = new MLDsaKeyPairGenerator();
        gen.Init(new MLDsaKeyGenerationParameters(_random, MLDsaParameters.ml_dsa_65));
        _keyPair = gen.GenerateKeyPair();
    }

    public void LoadKeyPair(AsymmetricCipherKeyPair keyPair)
    {
        if (_keyPair is not null)
            throw new InvalidOperationException(AlreadyInitializedMessage);

        _keyPair = keyPair;
    }

    public ISignatureFactory CreateSignatureFactory()
    {
        // BC 2.6.2 SignerUtilities recognizes the FIPS 204 name "ML-DSA-65"
        // and dispatches to MLDsaSigner internally. The factory's AlgorithmDetails
        // resolves to OID 2.16.840.1.101.3.4.3.18 in the cert's TBS.signature field.
        //
        // Note: ML-DSA in BC defaults to randomized (hedged) mode per FIPS 204.
        // Tests must verify by signature validation, not signature byte equality.
        return new Asn1SignatureFactory("ML-DSA-65", KeyPair.Private, _random);
    }
}

/// <summary>
/// FIPS 205 SLH-DSA-SHA2-256s signer. Hash-based signature scheme with
/// conservative security assumptions (no number-theoretic hardness — security
/// reduces to SHA-2 collision resistance).
///
/// Trade-offs: slow keygen (~1-3s) and slow signing (~100ms-1s), but small
/// signatures (~7.8KB) compared to the SHA2-256f variant (~35KB). Conservative
/// choice for root CAs that sign rarely and are stored long-term.
/// </summary>
public sealed class SlhDsaSigner : IPqSigner
{
    private const string AlreadyInitializedMessage =
        "GenerateKeyPair/LoadKeyPair must be called exactly once per instance.";

    private readonly SecureRandom _random = new();
    private AsymmetricCipherKeyPair? _keyPair;

    public string AlgorithmId => KnownAlgorithms.SlhDsa256s;

    public AsymmetricCipherKeyPair KeyPair
        => _keyPair ?? throw new InvalidOperationException(
            "Call GenerateKeyPair or LoadKeyPair before accessing KeyPair.");

    public void GenerateKeyPair()
    {
        if (_keyPair is not null)
            throw new InvalidOperationException(AlreadyInitializedMessage);

        var gen = new SlhDsaKeyPairGenerator();
        gen.Init(new SlhDsaKeyGenerationParameters(_random, SlhDsaParameters.slh_dsa_sha2_256s));
        _keyPair = gen.GenerateKeyPair();
    }

    public void LoadKeyPair(AsymmetricCipherKeyPair keyPair)
    {
        if (_keyPair is not null)
            throw new InvalidOperationException(AlreadyInitializedMessage);

        _keyPair = keyPair;
    }

    public ISignatureFactory CreateSignatureFactory()
    {
        // BC 2.6.2 SignerUtilities recognizes the FIPS 205 name "SLH-DSA-SHA2-256S"
        // and dispatches to SlhDsaSigner internally. The factory's AlgorithmDetails
        // resolves to OID 2.16.840.1.101.3.4.3.24 (id-slh-dsa-sha2-256s per the NIST
        // CSOR registry — note the 256s variant lives at .24, not .20 which is the
        // 128s variant) in the cert's TBS.signature field.
        return new Asn1SignatureFactory("SLH-DSA-SHA2-256S", KeyPair.Private, _random);
    }
}

/// <summary>
/// Composes a classical primary signer with a post-quantum alt signer to
/// produce hybrid certs (X.509:2019 alt-sig extensions). The cert's standard
/// SubjectPublicKeyInfo carries the primary key; the alt key + alt sig live
/// in non-critical extensions per HybridExtensions.
///
/// Backward-compatible: legacy verifiers see a normal classical cert and
/// ignore the unknown extensions; PQ-aware verifiers can validate the alt
/// chain. The actual two-pass TBS signing happens in Task 6.3's
/// CertificateBuilder hybrid path — HybridSigner just holds both signers.
/// </summary>
public sealed class HybridSigner : IPqSigner
{
    public IPqSigner PrimarySigner { get; }
    public IPqSigner AltSigner { get; }

    public HybridSigner(IPqSigner primary, IPqSigner alt)
    {
        ArgumentNullException.ThrowIfNull(primary);
        ArgumentNullException.ThrowIfNull(alt);
        PrimarySigner = primary;
        AltSigner = alt;
    }

    public string AlgorithmId => KnownAlgorithms.Hybrid;

    /// <summary>
    /// Returns the PRIMARY signer's keypair so the cert's standard
    /// SubjectPublicKeyInfo field carries the classical key. The alt key
    /// is exposed via <see cref="AltSigner"/> and emitted into the cert's
    /// subjectAltPublicKeyInfo extension by the cert builder.
    /// </summary>
    public AsymmetricCipherKeyPair KeyPair => PrimarySigner.KeyPair;

    /// <summary>
    /// Initializes both inner signers. Each inner signer enforces the
    /// "GenerateKeyPair/LoadKeyPair must be called exactly once" contract,
    /// so calling this twice cascades to InvalidOperationException from
    /// the first inner signer.
    /// </summary>
    public void GenerateKeyPair()
    {
        PrimarySigner.GenerateKeyPair();
        AltSigner.GenerateKeyPair();
    }

    public void LoadKeyPair(AsymmetricCipherKeyPair keyPair)
        => throw new NotSupportedException(
            "HybridSigner requires loading both primary and alt key pairs separately " +
            "via PrimarySigner.LoadKeyPair and AltSigner.LoadKeyPair.");

    /// <summary>
    /// Returns the primary signer's signature factory. The cert's primary
    /// signature is computed via this factory; the alt signature is computed
    /// separately via AltSigner.CreateSignatureFactory in the cert builder's
    /// hybrid path (Task 6.3).
    /// </summary>
    public ISignatureFactory CreateSignatureFactory() => PrimarySigner.CreateSignatureFactory();
}

public static class SignerFactory
{
    private static readonly ImmutableArray<string> _supported =
        ImmutableArray.Create(KnownAlgorithms.Rsa4096, KnownAlgorithms.MlDsa65, KnownAlgorithms.SlhDsa256s, KnownAlgorithms.Hybrid);

    public static IPqSigner Create(string algorithmId)
    {
        ArgumentNullException.ThrowIfNull(algorithmId);

        return algorithmId switch
        {
            KnownAlgorithms.Rsa4096 => new RsaSigner(),
            KnownAlgorithms.MlDsa65 => new MlDsaSigner(),
            KnownAlgorithms.SlhDsa256s => new SlhDsaSigner(),
            KnownAlgorithms.Hybrid => new HybridSigner(new RsaSigner(), new MlDsaSigner()),
            _ => throw new ArgumentException(
                $"Unknown signing algorithm: '{algorithmId}'. Supported: {string.Join(", ", _supported)}.",
                nameof(algorithmId))
        };
    }

    public static ImmutableArray<string> SupportedAlgorithms => _supported;

    /// <summary>
    /// Inspects the signature algorithm OID on a loaded cert and returns
    /// a fresh signer of the matching algorithm. Used when issuing leaf
    /// certs so the leaf is signed by the same algorithm as the CA.
    ///
    /// Hybrid certs are NOT detected here — their primary signature OID
    /// is just sha256WithRSAEncryption (looks like a plain RSA cert).
    /// Hybrid detection requires inspecting the subjectAltPublicKeyInfo
    /// extension and is handled separately (see Task 6.8).
    /// </summary>
    public static IPqSigner CreateForCertificate(
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        string? oid = cert.SignatureAlgorithm.Value;
        return oid switch
        {
            "1.2.840.113549.1.1.11" => new RsaSigner(),       // sha256WithRSAEncryption
            "2.16.840.1.101.3.4.3.18" => new MlDsaSigner(),   // id-ml-dsa-65
            "2.16.840.1.101.3.4.3.24" => new SlhDsaSigner(),  // id-slh-dsa-sha2-256s (FIPS 205, per NIST CSOR)
            _ => throw new NotSupportedException(
                $"Cannot determine signer for CA with signature algorithm OID '{oid ?? "<null>"}'.")
        };
    }
}
