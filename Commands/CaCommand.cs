// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

public static class CaCommand
{
    public static Command Build()
    {
        var nameArg = new Argument<string>("certificateName") { Description = "CN for the root CA." };
        var passArg = new Argument<string>("certificatePassword") { Description = "Password to secure the PFX." };
        var dirArg = new Argument<string>("exportDirectory") { Description = "Directory where the PFX will be written." };

        var algoOpt = new Option<string>("--algorithm")
        {
            Description = $"Signing algorithm. Supported: {string.Join(", ", Pq.SignerFactory.SupportedAlgorithms)}. Default: {Pq.KnownAlgorithms.Rsa4096}.",
            DefaultValueFactory = _ => Pq.KnownAlgorithms.Rsa4096,
        };

        var cmd = new Command("ca", "Generate a self-signed root CA certificate.");
        cmd.Add(nameArg);
        cmd.Add(passArg);
        cmd.Add(dirArg);
        cmd.Add(algoOpt);

        cmd.SetAction(parseResult =>
        {
            var name = parseResult.GetValue(nameArg)!;
            var pwd = parseResult.GetValue(passArg)!;
            var dir = parseResult.GetValue(dirArg)!;
            var algo = parseResult.GetValue(algoOpt)!;

            Common.EnsureDirectoryExists(dir);

            var signer = Pq.SignerFactory.Create(algo);
            signer.GenerateKeyPair();
            var (cert, pfxBytes) = Pq.CertificateBuilder.BuildCertificateWithPfx(new Pq.CertificateSpec(
                Pq.CertificatePurpose.RootCa, name, pwd, signer,
                ServerIp: null, EmailAddress: null, Issuer: null));

            Console.WriteLine($"Algorithm = {algo}");
            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, pfxBytes);
            Console.WriteLine("Certificate exported to " + path);
        });

        return cmd;
    }
}
