// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using FluentAssertions;
using Soverance.Certifactory.Pq;
using Xunit;

namespace Certifactory.Tests;

public class SigningTests
{
    [Fact]
    public void RsaSigner_generates_4096_bit_key()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        signer.AlgorithmId.Should().Be(KnownAlgorithms.Rsa4096);
        signer.KeyPair.Should().NotBeNull();
        signer.KeyPair.Public.Should().NotBeNull();
        signer.KeyPair.Private.Should().NotBeNull();
    }

    [Fact]
    public void RsaSigner_creates_signature_factory()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        signer.CreateSignatureFactory().Should().NotBeNull();
    }

    [Fact]
    public void RsaSigner_KeyPair_throws_when_read_before_init()
    {
        var signer = new RsaSigner();
        Action act = () => _ = signer.KeyPair;
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void RsaSigner_CreateSignatureFactory_throws_before_init()
    {
        var signer = new RsaSigner();
        Action act = () => signer.CreateSignatureFactory();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void RsaSigner_GenerateKeyPair_twice_throws()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        Action act = () => signer.GenerateKeyPair();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void RsaSigner_LoadKeyPair_after_GenerateKeyPair_throws()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        var existingKeypair = signer.KeyPair;
        Action act = () => signer.LoadKeyPair(existingKeypair);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SignerFactory_creates_rsa_signer()
    {
        IPqSigner s = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        s.Should().BeOfType<RsaSigner>();
    }

    [Fact]
    public void SignerFactory_throws_on_unknown_algorithm()
    {
        Action act = () => SignerFactory.Create("bogus-algo");
        act.Should().Throw<ArgumentException>()
            .WithMessage("*bogus-algo*")
            .WithMessage("*rsa-4096*");
    }

    [Fact]
    public void SignerFactory_throws_on_null_algorithm()
    {
        Action act = () => SignerFactory.Create(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void SignerFactory_SupportedAlgorithms_includes_rsa_4096()
    {
        SignerFactory.SupportedAlgorithms.Should().Contain(KnownAlgorithms.Rsa4096);
    }
}
