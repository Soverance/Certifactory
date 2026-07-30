// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan;

using System.Text.Json.Serialization;

/// <summary>Root CycloneDX 1.6 BOM document (CBOM profile).</summary>
public sealed class CbomDocument
{
    [JsonPropertyName("bomFormat")]   public string BomFormat { get; set; } = "CycloneDX";
    [JsonPropertyName("specVersion")] public string SpecVersion { get; set; } = "1.6";
    [JsonPropertyName("version")]     public int Version { get; set; } = 1;
    [JsonPropertyName("metadata")]    public Metadata? Metadata { get; set; }
    [JsonPropertyName("components")]  public List<Component> Components { get; set; } = new();
    [JsonPropertyName("dependencies")] public List<Dependency> Dependencies { get; set; } = new();
}

public sealed class Metadata
{
    [JsonPropertyName("timestamp")] public string? Timestamp { get; set; }
    [JsonPropertyName("tools")]     public ToolsSection? Tools { get; set; }
    [JsonPropertyName("component")] public Component? Component { get; set; }
}

public sealed class ToolsSection
{
    [JsonPropertyName("components")] public List<ToolComponent> Components { get; set; } = new();
}

public sealed class ToolComponent
{
    [JsonPropertyName("type")]      public string Type { get; set; } = "application";
    [JsonPropertyName("name")]      public string Name { get; set; } = "";
    [JsonPropertyName("version")]   public string Version { get; set; } = "";
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
}

public sealed class Component
{
    [JsonPropertyName("type")]             public string Type { get; set; } = "";
    [JsonPropertyName("bom-ref")]          public string BomRef { get; set; } = "";
    [JsonPropertyName("name")]             public string Name { get; set; } = "";
    [JsonPropertyName("properties")]       public List<Property>? Properties { get; set; }
    [JsonPropertyName("cryptoProperties")] public CryptoProperties? CryptoProperties { get; set; }
}

public sealed class Property
{
    [JsonPropertyName("name")]  public string Name { get; set; } = "";
    [JsonPropertyName("value")] public string Value { get; set; } = "";
}

public sealed class CryptoProperties
{
    [JsonPropertyName("assetType")]                     public string AssetType { get; set; } = "";
    [JsonPropertyName("algorithmProperties")]           public AlgorithmProperties? AlgorithmProperties { get; set; }
    [JsonPropertyName("certificateProperties")]         public CertificateProperties? CertificateProperties { get; set; }
    [JsonPropertyName("relatedCryptoMaterialProperties")] public RelatedCryptoMaterialProperties? RelatedCryptoMaterialProperties { get; set; }
    [JsonPropertyName("protocolProperties")]            public ProtocolProperties? ProtocolProperties { get; set; }
    [JsonPropertyName("oid")]                           public string? Oid { get; set; }
}

public sealed class ProtocolProperties
{
    [JsonPropertyName("type")]         public string Type { get; set; } = "tls";
    [JsonPropertyName("version")]      public string? Version { get; set; }
    [JsonPropertyName("cipherSuites")] public List<CipherSuite>? CipherSuites { get; set; }
}

public sealed class CipherSuite
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
}

public sealed class AlgorithmProperties
{
    [JsonPropertyName("primitive")]                public string Primitive { get; set; } = "";
    [JsonPropertyName("parameterSetIdentifier")]   public string? ParameterSetIdentifier { get; set; }
    [JsonPropertyName("cryptoFunctions")]          public List<string>? CryptoFunctions { get; set; }
    [JsonPropertyName("classicalSecurityLevel")]   public int? ClassicalSecurityLevel { get; set; }
    [JsonPropertyName("nistQuantumSecurityLevel")] public int? NistQuantumSecurityLevel { get; set; }
}

public sealed class CertificateProperties
{
    [JsonPropertyName("subjectName")]           public string SubjectName { get; set; } = "";
    [JsonPropertyName("issuerName")]            public string IssuerName { get; set; } = "";
    [JsonPropertyName("notValidBefore")]        public string NotValidBefore { get; set; } = "";
    [JsonPropertyName("notValidAfter")]         public string NotValidAfter { get; set; } = "";
    [JsonPropertyName("signatureAlgorithmRef")] public string? SignatureAlgorithmRef { get; set; }
    [JsonPropertyName("subjectPublicKeyRef")]   public string? SubjectPublicKeyRef { get; set; }
    [JsonPropertyName("certificateFormat")]     public string CertificateFormat { get; set; } = "X.509";
}

public sealed class RelatedCryptoMaterialProperties
{
    [JsonPropertyName("type")]         public string Type { get; set; } = "";
    [JsonPropertyName("algorithmRef")] public string? AlgorithmRef { get; set; }
    [JsonPropertyName("size")]         public int? Size { get; set; }
    [JsonPropertyName("state")]        public string State { get; set; } = "active";
}

public sealed class Dependency
{
    [JsonPropertyName("ref")]       public string Ref { get; set; } = "";
    [JsonPropertyName("dependsOn")] public List<string> DependsOn { get; set; } = new();
}
