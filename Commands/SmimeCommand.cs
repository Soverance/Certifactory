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
        var caArg = new Argument<string>("rootCA") { Description = "Path to the root CA PFX file." };
        var caPassArg = new Argument<string>("rootCAPassword") { Description = "Password for the root CA PFX." };
        var dirArg = new Argument<string>("exportDirectory") { Description = "Directory where the PFX will be written." };

        var cmd = new Command("smime", "Generate an S/MIME certificate signed by a root CA.");
        cmd.Add(nameArg);
        cmd.Add(passArg);
        cmd.Add(emailArg);
        cmd.Add(caArg);
        cmd.Add(caPassArg);
        cmd.Add(dirArg);
        cmd.SetAction(parseResult =>
        {
            var name = parseResult.GetValue(nameArg)!;
            var pwd = parseResult.GetValue(passArg)!;
            var email = parseResult.GetValue(emailArg)!;
            var ca = parseResult.GetValue(caArg)!;
            var caPwd = parseResult.GetValue(caPassArg)!;
            var dir = parseResult.GetValue(dirArg)!;
            Common.EnsureDirectoryExists(dir);
            X509Certificate2 cert = Cryptography.buildSelfSignedSmimeCertificate(name, pwd, email, ca, caPwd);
            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            byte[] data = cert.Export(X509ContentType.Pfx, pwd);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, data);
            Console.WriteLine("Certificate exported to " + path);
        });
        return cmd;
    }
}
