// VERIFIED API SURFACE - BouncyCastle.Cryptography 2.6.2
//   ML-DSA generator:  Org.BouncyCastle.Crypto.Generators.MLDsaKeyPairGenerator
//   ML-DSA parameters: Org.BouncyCastle.Crypto.Parameters.{MLDsaKeyGenerationParameters, MLDsaParameters}
//                      MLDsaParameters static fields: ml_dsa_44, ml_dsa_65, ml_dsa_87
//                      (also *_with_sha512 prehash variants)
//   ML-DSA signers:    Org.BouncyCastle.Crypto.Signers.{MLDsaSigner, HashMLDsaSigner}
//
//   SLH-DSA generator: Org.BouncyCastle.Crypto.Generators.SlhDsaKeyPairGenerator
//   SLH-DSA params:    Org.BouncyCastle.Crypto.Parameters.{SlhDsaKeyGenerationParameters, SlhDsaParameters}
//                      SlhDsaParameters static fields: slh_dsa_sha2_{128,192,256}{s,f},
//                      slh_dsa_shake_{128,192,256}{s,f} (plus *_with_* prehash variants)
//   SLH-DSA signers:   Org.BouncyCastle.Crypto.Signers.{SlhDsaSigner, HashSlhDsaSigner}
//
// NOTE: The original plan placed these under Org.BouncyCastle.Pqc.Crypto.MLDsa /
// Org.BouncyCastle.Pqc.Crypto.SlhDsa. In BC.Cryptography 2.6.2 the FIPS 204 / 205
// types live under Org.BouncyCastle.Crypto.{Generators,Parameters,Signers} instead.
// The Pqc.Crypto.* namespace still hosts the legacy pre-FIPS algorithms
// (Crystals.Dilithium, SphincsPlus, etc.). All subsequent production code in this
// project must target the Crypto.{Generators,Parameters,Signers} types verified here.
//
// Bonus for later phases:
//   ML-KEM:  Org.BouncyCastle.Crypto.Generators.MLKemKeyPairGenerator
//            Org.BouncyCastle.Crypto.Parameters.{MLKemKeyGenerationParameters, MLKemParameters}
//            Org.BouncyCastle.Crypto.Kems.{MLKemEncapsulator, MLKemDecapsulator}
//
// ---- Signer usage (verified by reflection against BC 2.6.2) ----
// Both MLDsaSigner and SlhDsaSigner implement Org.BouncyCastle.Crypto.ISigner with
// the following non-obvious specifics:
//
//   1. The constructor is NOT no-arg. It takes:
//        new MLDsaSigner(MLDsaParameters parameters, bool deterministic)
//        new SlhDsaSigner(SlhDsaParameters parameters, bool deterministic)
//      The `parameters` argument must match the parameter set that produced the
//      key (e.g. ml_dsa_65, slh_dsa_sha2_256s). `deterministic: true` makes the
//      signature reproducible (no per-sign randomness); set false for the
//      randomized "hedged" variant. We use `true` here for stable canary output.
//
//   2. Init(bool forSigning, ICipherParameters key)
//        - forSigning=true  -> pass the private key (kp.Private)
//        - forSigning=false -> pass the public  key (kp.Public)
//      (NOT InitForSigning / InitForVerifying; standard BC ISigner shape.)
//
//   3. Feed input via BlockUpdate(byte[] buf, int off, int len) (or Update(byte),
//      or BlockUpdate(ReadOnlySpan<byte>)). Multiple BlockUpdate calls accumulate.
//
//   4. byte[] sig = signer.GenerateSignature();   // when forSigning=true
//      bool ok  = signer.VerifySignature(sig);    // when forSigning=false
//
// Tasks 4.1 (sign) and 5.1 (verify) should follow exactly this shape.
//
// (Update this header if BC surface changes; subsequent production code must match.)

using System.Text;
using FluentAssertions;
using Org.BouncyCastle.Security;
using Xunit;

namespace Certifactory.Tests;

public class PqApiSpike
{
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("certifactory pq spike");

    [Fact]
    public void MlDsa_sign_verify_roundtrip()
    {
        var random = new SecureRandom();
        var parameters = Org.BouncyCastle.Crypto.Parameters.MLDsaParameters.ml_dsa_65;

        var keyGen = new Org.BouncyCastle.Crypto.Generators.MLDsaKeyPairGenerator();
        keyGen.Init(new Org.BouncyCastle.Crypto.Parameters.MLDsaKeyGenerationParameters(
            random, parameters));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();
        kp.Public.Should().NotBeNull();
        kp.Private.Should().NotBeNull();

        // Sign with the private key.
        var signer = new Org.BouncyCastle.Crypto.Signers.MLDsaSigner(parameters, deterministic: true);
        signer.Init(forSigning: true, kp.Private);
        signer.BlockUpdate(Message, 0, Message.Length);
        byte[] signature = signer.GenerateSignature();
        signature.Should().NotBeNullOrEmpty();

        // Verify with the public key (fresh signer instance).
        var verifier = new Org.BouncyCastle.Crypto.Signers.MLDsaSigner(parameters, deterministic: true);
        verifier.Init(forSigning: false, kp.Public);
        verifier.BlockUpdate(Message, 0, Message.Length);
        verifier.VerifySignature(signature).Should().BeTrue();
    }

    [Fact]
    public void SlhDsa_sign_verify_roundtrip()
    {
        var random = new SecureRandom();
        var parameters = Org.BouncyCastle.Crypto.Parameters.SlhDsaParameters.slh_dsa_sha2_256s;

        var keyGen = new Org.BouncyCastle.Crypto.Generators.SlhDsaKeyPairGenerator();
        keyGen.Init(new Org.BouncyCastle.Crypto.Parameters.SlhDsaKeyGenerationParameters(
            random, parameters));
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();
        kp.Public.Should().NotBeNull();
        kp.Private.Should().NotBeNull();

        // Sign with the private key.
        var signer = new Org.BouncyCastle.Crypto.Signers.SlhDsaSigner(parameters, deterministic: true);
        signer.Init(forSigning: true, kp.Private);
        signer.BlockUpdate(Message, 0, Message.Length);
        byte[] signature = signer.GenerateSignature();
        signature.Should().NotBeNullOrEmpty();

        // Verify with the public key (fresh signer instance).
        var verifier = new Org.BouncyCastle.Crypto.Signers.SlhDsaSigner(parameters, deterministic: true);
        verifier.Init(forSigning: false, kp.Public);
        verifier.BlockUpdate(Message, 0, Message.Length);
        verifier.VerifySignature(signature).Should().BeTrue();
    }
}
