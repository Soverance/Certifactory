// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using FluentAssertions;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan;

public class CbomSerializerTests
{
    [Fact]
    public void Serializes_hyphenated_and_cased_property_names_and_omits_nulls()
    {
        var doc = new CbomDocument
        {
            Metadata = new Metadata
            {
                Timestamp = "2026-07-27T00:00:00Z",
                Tools = new ToolsSection { Components = new() { new ToolComponent { Name = "certifactory", Version = "1.0.0" } } },
                Component = new Component { Type = "platform", BomRef = "host:TESTHOST", Name = "TESTHOST" }
            },
            Components = new()
            {
                new Component
                {
                    Type = "cryptographic-asset",
                    BomRef = "alg:rsa",
                    Name = "RSA with SHA-256",
                    CryptoProperties = new CryptoProperties
                    {
                        AssetType = "algorithm",
                        Oid = "1.2.840.113549.1.1.11",
                        AlgorithmProperties = new AlgorithmProperties
                        {
                            Primitive = "signature",
                            NistQuantumSecurityLevel = 0
                        }
                    }
                }
            },
            Dependencies = new() { new Dependency { Ref = "cert:x", DependsOn = new() { "alg:rsa" } } }
        };

        var json = CbomSerializer.Serialize(doc);
        using var parsed = JsonDocument.Parse(json);
        var root = parsed.RootElement;

        root.GetProperty("bomFormat").GetString().Should().Be("CycloneDX");
        root.GetProperty("specVersion").GetString().Should().Be("1.6");
        root.GetProperty("version").GetInt32().Should().Be(1);

        var comp = root.GetProperty("components")[0];
        comp.GetProperty("type").GetString().Should().Be("cryptographic-asset");
        comp.GetProperty("bom-ref").GetString().Should().Be("alg:rsa"); // hyphenated key
        comp.GetProperty("cryptoProperties").GetProperty("assetType").GetString().Should().Be("algorithm");

        var alg = comp.GetProperty("cryptoProperties").GetProperty("algorithmProperties");
        alg.GetProperty("nistQuantumSecurityLevel").GetInt32().Should().Be(0);
        // Null fields omitted: parameterSetIdentifier was never set.
        alg.TryGetProperty("parameterSetIdentifier", out _).Should().BeFalse();

        root.GetProperty("dependencies")[0].GetProperty("dependsOn")[0].GetString().Should().Be("alg:rsa");
    }

    [Fact]
    public void Deserialize_round_trips_components_and_properties()
    {
        var doc = new CbomDocument
        {
            Components =
            {
                new Component
                {
                    Type = "cryptographic-asset",
                    BomRef = "cert:aa",
                    Name = "CN=x",
                    Properties = new List<Property>
                    {
                        new() { Name = "certifactory:certificate:role", Value = "root-ca" }
                    },
                    CryptoProperties = new CryptoProperties { AssetType = "certificate" }
                }
            }
        };

        var json = CbomSerializer.Serialize(doc);
        var back = CbomSerializer.Deserialize(json);

        var comp = back!.Components.Single();
        comp.BomRef.Should().Be("cert:aa");
        comp.Properties!.Single().Name.Should().Be("certifactory:certificate:role");
        comp.Properties!.Single().Value.Should().Be("root-ca");
        comp.CryptoProperties!.AssetType.Should().Be("certificate");
    }
}
