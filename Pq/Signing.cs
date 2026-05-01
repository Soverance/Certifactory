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

public static class SignerFactory
{
    private static readonly ImmutableArray<string> _supported =
        ImmutableArray.Create(KnownAlgorithms.Rsa4096);

    public static IPqSigner Create(string algorithmId)
    {
        ArgumentNullException.ThrowIfNull(algorithmId);

        return algorithmId switch
        {
            KnownAlgorithms.Rsa4096 => new RsaSigner(),
            _ => throw new ArgumentException(
                $"Unknown signing algorithm: '{algorithmId}'. Supported: {string.Join(", ", _supported)}.",
                nameof(algorithmId))
        };
    }

    public static ImmutableArray<string> SupportedAlgorithms => _supported;
}
