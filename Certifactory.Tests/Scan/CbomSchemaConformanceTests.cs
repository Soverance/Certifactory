// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Json.Schema;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan;

public class CbomSchemaConformanceTests
{
    private static JsonSchema LoadSchemaAndRegisterRefs()
    {
        // Register the two referenced schemas by the absolute cyclonedx.org URIs
        // that bom-1.6's relative $refs resolve to, then return the bom schema.
        Register("spdx.schema.json",     "http://cyclonedx.org/schema/spdx.schema.json");
        Register("jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json");
        return JsonSchema.FromText(ReadResource("bom-1.6.schema.json"));
    }

    private static void Register(string resource, string uri)
    {
        var schema = JsonSchema.FromText(ReadResource(resource));
        SchemaRegistry.Global.Register(new Uri(uri), schema);
    }

    private static string ReadResource(string fileName)
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().Single(n => n.EndsWith(fileName));
        using var s = asm.GetManifestResourceStream(name)!;
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    private static DiscoveredCertificate SampleCert() => new(
        SubjectName: "CN=schema.example.com", IssuerName: "CN=root",
        NotBefore: new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        NotAfter: new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        Sha256Thumbprint: "abc123",
        SignatureAlgorithmOid: "1.2.840.113549.1.1.11",
        SubjectKeyAlgorithmOid: "1.2.840.113549.1.1.1",
        SubjectKeySizeBits: 4096,
        IsHybrid: false, AltSignatureAlgorithmOid: null, AltKeyAlgorithmOid: null,
        SourceDescription: "src");

    [Fact]
    public void Built_cbom_validates_against_cyclonedx_1_6_schema()
    {
        var cert = SampleCert();

        var doc = CbomBuilder.Build(new[] { cert }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");
        var json = CbomSerializer.Serialize(doc);

        var schema = LoadSchemaAndRegisterRefs();
        var node = JsonNode.Parse(json);
        var result = schema.Evaluate(node, new EvaluationOptions { OutputFormat = OutputFormat.List });

        result.IsValid.Should().BeTrue(
            because: "emitted CBOM must be schema-valid CycloneDX 1.6; errors: " +
                     JsonSerializer.Serialize(result.Details));
    }

    // Carried finding from Task 2 review: schema validation alone will not catch a
    // misnamed OPTIONAL field if the schema permits additional properties. Lock the
    // exact JSON key spelling for the certificate and key crypto-property blocks by
    // walking the raw serialized JSON, independent of the C# model's property names.
    [Fact]
    public void Certificate_and_key_crypto_properties_use_exact_cyclonedx_key_names()
    {
        var cert = SampleCert();
        var doc = CbomBuilder.Build(new[] { cert }, "HOST", "2026-07-27T00:00:00Z", "1.0.0");
        var json = CbomSerializer.Serialize(doc);

        using var parsed = JsonDocument.Parse(json);
        var components = parsed.RootElement.GetProperty("components");

        JsonElement? certificateComponent = null;
        JsonElement? keyComponent = null;
        foreach (var component in components.EnumerateArray())
        {
            if (!component.TryGetProperty("cryptoProperties", out var cryptoProperties)) continue;
            if (!cryptoProperties.TryGetProperty("assetType", out var assetType)) continue;

            var assetTypeValue = assetType.GetString();
            if (assetTypeValue == "certificate") certificateComponent = component;
            else if (assetTypeValue == "related-crypto-material") keyComponent = component;
        }

        certificateComponent.Should().NotBeNull("the CBOM should contain a certificate component");
        keyComponent.Should().NotBeNull("the CBOM should contain a related-crypto-material (key) component");

        var certificateProperties = certificateComponent!.Value
            .GetProperty("cryptoProperties")
            .GetProperty("certificateProperties");

        foreach (var key in new[]
        {
            "subjectName", "issuerName", "notValidBefore", "notValidAfter",
            "signatureAlgorithmRef", "subjectPublicKeyRef", "certificateFormat"
        })
        {
            certificateProperties.TryGetProperty(key, out _).Should().BeTrue(
                $"certificateProperties should contain the exact key '{key}'");
        }

        var relatedCryptoMaterialProperties = keyComponent!.Value
            .GetProperty("cryptoProperties")
            .GetProperty("relatedCryptoMaterialProperties");

        foreach (var key in new[] { "algorithmRef", "size", "state" })
        {
            relatedCryptoMaterialProperties.TryGetProperty(key, out _).Should().BeTrue(
                $"relatedCryptoMaterialProperties should contain the exact key '{key}'");
        }
    }
}
