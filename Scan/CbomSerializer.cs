// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// Serializes a <see cref="CbomDocument"/> to CycloneDX 1.6 JSON. Property names
/// come from explicit [JsonPropertyName] attributes on the model (so the
/// hyphenated "bom-ref" and mixed-case CycloneDX names are exact); nulls are
/// omitted so optional fields don't appear as JSON null.
/// </summary>
public static class CbomSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Serialize(CbomDocument doc) => JsonSerializer.Serialize(doc, Options);

    public static CbomDocument? Deserialize(string json) =>
        JsonSerializer.Deserialize<CbomDocument>(json, Options);
}
