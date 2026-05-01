// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Pq;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;

/// <summary>
/// Algorithm-agnostic signing primitive used by CertificateBuilder.
/// One instance carries one keypair; create a fresh instance per cert.
/// </summary>
/// <remarks>
/// Lifecycle: call <see cref="GenerateKeyPair"/> OR <see cref="LoadKeyPair"/>
/// exactly once before reading <see cref="KeyPair"/> or calling
/// <see cref="CreateSignatureFactory"/>. Implementations throw
/// <see cref="System.InvalidOperationException"/> on any pre-init access.
///
/// The BouncyCastle types (<see cref="AsymmetricCipherKeyPair"/>,
/// <see cref="ISignatureFactory"/>) are intentional dependencies — BC is
/// currently the only viable PQ library on net8.0. When the .NET BCL gains
/// X.509 support for native MLDsa/SlhDsa types, this seam is the swap point.
/// </remarks>
public interface IPqSigner
{
    /// <summary>Stable identifier used by SignerFactory and CLI (e.g. "rsa-4096", "ml-dsa-65").</summary>
    string AlgorithmId { get; }

    /// <summary>The keypair produced by <see cref="GenerateKeyPair"/> or supplied via <see cref="LoadKeyPair"/>.</summary>
    /// <exception cref="System.InvalidOperationException">Thrown if read before initialization.</exception>
    AsymmetricCipherKeyPair KeyPair { get; }

    /// <summary>Generate and store a fresh keypair on this signer instance.</summary>
    /// <remarks>Mutually exclusive with <see cref="LoadKeyPair"/>; call exactly one, exactly once.</remarks>
    void GenerateKeyPair();

    /// <summary>Load an existing keypair (used when issuing leaf certs from a CA's private key).</summary>
    /// <remarks>Mutually exclusive with <see cref="GenerateKeyPair"/>; call exactly one, exactly once.</remarks>
    void LoadKeyPair(AsymmetricCipherKeyPair keyPair);

    /// <summary>BC signature factory used by X509V3CertificateGenerator.</summary>
    /// <exception cref="System.InvalidOperationException">Thrown if called before initialization.</exception>
    ISignatureFactory CreateSignatureFactory();
}
