// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using FluentAssertions;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan;

public class QuantumClassifierTests
{
    [Fact]
    public void Rsa_signature_oid_is_quantum_vulnerable()
    {
        var c = QuantumClassifier.Classify("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
        c.Name.Should().Be("RSA with SHA-256");
        c.Primitive.Should().Be("signature");
        c.Readiness.Should().Be(PqReadiness.Vulnerable);
        c.NistQuantumSecurityLevel.Should().Be(0);
    }

    [Fact]
    public void Rsa_key_oid_is_quantum_vulnerable_pke()
    {
        var c = QuantumClassifier.Classify("1.2.840.113549.1.1.1"); // rsaEncryption
        c.Primitive.Should().Be("pke");
        c.Readiness.Should().Be(PqReadiness.Vulnerable);
    }

    [Fact]
    public void MlDsa65_oid_is_quantum_safe_level_3()
    {
        var c = QuantumClassifier.Classify("2.16.840.1.101.3.4.3.18"); // id-ml-dsa-65
        c.Name.Should().Be("ML-DSA-65");
        c.Primitive.Should().Be("signature");
        c.Readiness.Should().Be(PqReadiness.QuantumSafe);
        c.NistQuantumSecurityLevel.Should().Be(3);
        c.ParameterSetIdentifier.Should().Be("65");
    }

    [Fact]
    public void SlhDsa256s_oid_is_quantum_safe_level_5()
    {
        var c = QuantumClassifier.Classify("2.16.840.1.101.3.4.3.24"); // id-slh-dsa-sha2-256s
        c.Name.Should().Be("SLH-DSA-SHA2-256s");
        c.Readiness.Should().Be(PqReadiness.QuantumSafe);
        c.NistQuantumSecurityLevel.Should().Be(5);
    }

    [Fact]
    public void Unknown_oid_is_not_applicable()
    {
        var c = QuantumClassifier.Classify("1.2.3.4.5");
        c.Readiness.Should().Be(PqReadiness.NotApplicable);
        c.Primitive.Should().Be("unknown");
        c.Name.Should().Contain("1.2.3.4.5");
    }

    [Fact]
    public void Null_or_empty_oid_returns_not_applicable_without_throwing()
    {
        var fromNull = QuantumClassifier.Classify(null!);
        fromNull.Readiness.Should().Be(PqReadiness.NotApplicable);
        fromNull.Primitive.Should().Be("unknown");

        var fromEmpty = QuantumClassifier.Classify("");
        fromEmpty.Readiness.Should().Be(PqReadiness.NotApplicable);
    }
}
