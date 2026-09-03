// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

public static class CodeSignCommand
{
    public static Command Build()
    {
        var nameArg = new Argument<string>("certificateName") { Description = "CN for the code-signing certificate." };
        var passArg = new Argument<string>("certificatePassword") { Description = "Password to secure the PFX." };
        var caArg = new Argument<string>("rootCA") { Description = "Absolute path to the root CA PFX." };
        var caPassArg = new Argument<string>("rootCAPassword") { Description = "Password for the root CA PFX." };
        var dirArg = new Argument<string>("exportDirectory") { Description = "Directory where the PFX will be written." };

        var algoOpt = new Option<string>("--algorithm")
        {
            Description = $"Signing algorithm for the leaf cert. Supported: {string.Join(", ", Pq.SignerFactory.SupportedAlgorithms)}. Default: {Pq.KnownAlgorithms.Rsa4096}. (CA's algorithm is detected from the loaded PFX.)",
            DefaultValueFactory = _ => Pq.KnownAlgorithms.Rsa4096,
        };
        var authenticodeOpt = new Option<bool>("--authenticode")
        {
            Description = "Add Microsoft code-signing OIDs (Individual Code Signing + Lifetime Signing) alongside the standard code-signing EKU.",
        };
        var orgOpt = new Option<string?>("--org")
        {
            Description = "Publisher organization (O=). When omitted, the subject uses the default Soverance Studios org block.",
        };

        var cmd = new Command("codesign", "Generate a code-signing certificate signed by a root CA.");
        cmd.Add(nameArg);
        cmd.Add(passArg);
        cmd.Add(caArg);
        cmd.Add(caPassArg);
        cmd.Add(dirArg);
        cmd.Add(algoOpt);
        cmd.Add(authenticodeOpt);
        cmd.Add(orgOpt);

        cmd.SetAction(parseResult =>
        {
            var name = parseResult.GetValue(nameArg)!;
            var pwd = parseResult.GetValue(passArg)!;
            var ca = parseResult.GetValue(caArg)!;
            var caPwd = parseResult.GetValue(caPassArg)!;
            var dir = parseResult.GetValue(dirArg)!;
            var algo = parseResult.GetValue(algoOpt)!;
            var authenticode = parseResult.GetValue(authenticodeOpt);
            var org = parseResult.GetValue(orgOpt);

            Common.EnsureDirectoryExists(dir);

            var caCert = new X509Certificate2(ca, caPwd,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            var caSigner = Common.LoadCaSigner(caCert, ca, caPwd);

            var leafSigner = Pq.SignerFactory.Create(algo);
            leafSigner.GenerateKeyPair();
            var (cert, pfxBytes) = Pq.CertificateBuilder.BuildCertificateWithPfx(new Pq.CertificateSpec(
                Pq.CertificatePurpose.CodeSigning, name, pwd, leafSigner,
                ServerIp: null,
                EmailAddress: null,
                Issuer: new Pq.IssuerInfo(caCert, caSigner),
                Organization: org,
                Authenticode: authenticode));

            Console.WriteLine($"Algorithm = {algo}");
            Console.WriteLine($"Authenticode OIDs = {authenticode}");
            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, pfxBytes);
            Console.WriteLine("Certificate exported to " + path);
        });

        return cmd;
    }
}
