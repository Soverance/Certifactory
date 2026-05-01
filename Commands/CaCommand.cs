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

        var cmd = new Command("ca", "Generate a self-signed root CA certificate.");
        cmd.Add(nameArg);
        cmd.Add(passArg);
        cmd.Add(dirArg);
        cmd.SetAction(parseResult =>
        {
            var name = parseResult.GetValue(nameArg)!;
            var pwd = parseResult.GetValue(passArg)!;
            var dir = parseResult.GetValue(dirArg)!;

            Common.EnsureDirectoryExists(dir);

            var signer = Pq.SignerFactory.Create(Pq.KnownAlgorithms.Rsa4096);
            signer.GenerateKeyPair();
            var cert = Pq.CertificateBuilder.BuildCertificate(new Pq.CertificateSpec(
                Pq.CertificatePurpose.RootCa, name, pwd, signer,
                ServerIp: null, EmailAddress: null, Issuer: null));

            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            byte[] data = cert.Export(X509ContentType.Pfx, pwd);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, data);
            Console.WriteLine("Certificate exported to " + path);
        });
        return cmd;
    }
}
