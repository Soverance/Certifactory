// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory;

using System;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Soverance.Certifactory.Pq;

public class Common
{
    public static string GetAssemblyVersion()
    {
        return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version!.ToString();
    }

    public static string GetBasePath()
    {
        string baseDir = "";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // the "old" ways of getting this path in standard .NET appear to be non-functional when deployed in a Core Linux environment
            // so for dotnet core, we'll get the actual process that invoked this function and gather it's file name, which can give us the root path
            using var processModule = System.Diagnostics.Process.GetCurrentProcess().MainModule;
            baseDir = Path.GetDirectoryName(processModule?.FileName)!;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // in windows environments we could use reflection to get the application base folder path
            // but we can also use easier functions such as "AppContext.BaseDirectory" or "AppDomain.CurrentDomain.BaseDirectory"
            baseDir = AppContext.BaseDirectory;
        }

        return baseDir;
    }

    public static string EnsureDirectoryExists(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (!Directory.Exists(fullPath))
        {
            Directory.CreateDirectory(fullPath);
            Console.WriteLine("Created directory: " + fullPath);
        }
        return fullPath;
    }

    public static byte[] GetRandomByteArray(int size)
    {
        byte[] b = new byte[size];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }

    /// <summary>
    /// Loads a CA certificate's signer from disk, populating the keypair(s)
    /// from the PFX. Detects hybrid CAs via the subjectAltPublicKeyInfo
    /// extension and loads BOTH the primary and alt private keys; for
    /// non-hybrid CAs, loads just the primary. Used by leaf-issuing CLI
    /// commands (server, smime).
    /// </summary>
    public static IPqSigner LoadCaSigner(X509Certificate2 caCert, string caPath, string caPassword)
    {
        var caSigner = SignerFactory.CreateForCertificate(caCert);
        if (caSigner is HybridSigner caHybrid)
        {
            var (primaryKp, altKp) = PfxExporter.ExtractHybridKeyPairs(caPath, caPassword);
            if (altKp is null)
            {
                throw new InvalidOperationException(
                    "Hybrid CA PFX is missing its alt private key. " +
                    "Was it generated with a pre-hybrid version of Certifactory?");
            }
            caHybrid.PrimarySigner.LoadKeyPair(primaryKp);
            caHybrid.AltSigner.LoadKeyPair(altKp);
        }
        else
        {
            caSigner.LoadKeyPair(PfxExporter.ExtractKeyPair(caPath, caPassword));
        }
        return caSigner;
    }
}