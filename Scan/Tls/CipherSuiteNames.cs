// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Scan.Tls;

using System.Reflection;
using BcCipherSuite = Org.BouncyCastle.Tls.CipherSuite;

/// <summary>
/// BouncyCastle 2.6.2 has no CipherSuite.GetText()/GetName() helper anywhere in the
/// assembly. Build the codepoint-to-name lookup once by reflecting the public static
/// int fields on Org.BouncyCastle.Tls.CipherSuite (326 entries as of 2.6.2) — cheap,
/// self-maintaining if BouncyCastle adds cipher suites later, no hardcoded table to
/// keep in sync. Lifted verbatim from the Task 1 spike finding.
/// </summary>
public static class CipherSuiteNames
{
    public static readonly IReadOnlyDictionary<int, string> Table = Build();

    private static Dictionary<int, string> Build() =>
        typeof(BcCipherSuite).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.FieldType == typeof(int))
            .GroupBy(f => (int)f.GetValue(null)!)
            .ToDictionary(g => g.Key, g => g.First().Name);
}
