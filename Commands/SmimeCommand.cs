// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

public static class SmimeCommand
{
    public static Command Build()
    {
        var nameArg = new Argument<string>("certificateName") { Description = "CN for the S/MIME certificate." };
        var passArg = new Argument<string>("certificatePassword") { Description = "Password to secure the PFX." };
        var emailArg = new Argument<string>("userEmail") { Description = "Email address embedded in the certificate." };
        var caArg = new Argument<string>("rootCA") { Description = "Absolute path to the root CA PFX." };
        var caPassArg = new Argument<string>("rootCAPassword") { Description = "Password for the root CA PFX." };
        var dirArg = new Argument<string>("exportDirectory") { Description = "Directory where the PFX will be written." };

        var algoOpt = new Option<string>("--algorithm")
        {
            Description = $"Signing algorithm for the leaf cert. Supported: {string.Join(", ", Pq.SignerFactory.SupportedAlgorithms)}. Default: {Pq.KnownAlgorithms.Rsa4096}. (CA's algorithm is detected from the loaded PFX.)",
            DefaultValueFactory = _ => Pq.KnownAlgorithms.Rsa4096,
        };

        var cmd = new Command("smime", "Generate an S/MIME certificate signed by a root CA.");
        cmd.Add(nameArg);
        cmd.Add(passArg);
        cmd.Add(emailArg);
        cmd.Add(caArg);
        cmd.Add(caPassArg);
        cmd.Add(dirArg);
        cmd.Add(algoOpt);

        cmd.SetAction(parseResult =>
        {
            var name = parseResult.GetValue(nameArg)!;
            var pwd = parseResult.GetValue(passArg)!;
            var email = parseResult.GetValue(emailArg)!;
            var ca = parseResult.GetValue(caArg)!;
            var caPwd = parseResult.GetValue(caPassArg)!;
            var dir = parseResult.GetValue(dirArg)!;
            var algo = parseResult.GetValue(algoOpt)!;

            Common.EnsureDirectoryExists(dir);

            var caCert = new X509Certificate2(ca, caPwd,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            var caSigner = Pq.SignerFactory.CreateForCertificate(caCert);
            caSigner.LoadKeyPair(Pq.PfxExporter.ExtractKeyPair(ca, caPwd));

            var leafSigner = Pq.SignerFactory.Create(algo);
            leafSigner.GenerateKeyPair();
            var (cert, pfxBytes) = Pq.CertificateBuilder.BuildCertificateWithPfx(new Pq.CertificateSpec(
                Pq.CertificatePurpose.Smime, name, pwd, leafSigner,
                ServerIp: null,
                EmailAddress: email,
                Issuer: new Pq.IssuerInfo(caCert, caSigner)));

            Console.WriteLine($"Algorithm = {algo}");
            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, pfxBytes);
            Console.WriteLine("Certificate exported to " + path);
        });

        return cmd;
    }
}
