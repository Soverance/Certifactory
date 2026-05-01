// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

public static class ServerCommand
{
    public static Command Build()
    {
        var nameArg = new Argument<string>("certificateName") { Description = "CN for the server certificate." };
        var passArg = new Argument<string>("certificatePassword") { Description = "Password to secure the PFX." };
        var ipArg = new Argument<string>("serverIP") { Description = "Server IP address for SAN (may be empty)." };
        var caArg = new Argument<string>("rootCA") { Description = "Path to the root CA PFX file." };
        var caPassArg = new Argument<string>("rootCAPassword") { Description = "Password for the root CA PFX." };
        var dirArg = new Argument<string>("exportDirectory") { Description = "Directory where the PFX will be written." };

        var cmd = new Command("server", "Generate a server certificate signed by a root CA.");
        cmd.Add(nameArg);
        cmd.Add(passArg);
        cmd.Add(ipArg);
        cmd.Add(caArg);
        cmd.Add(caPassArg);
        cmd.Add(dirArg);
        cmd.SetAction(parseResult =>
        {
            var name = parseResult.GetValue(nameArg)!;
            var pwd = parseResult.GetValue(passArg)!;
            var ip = parseResult.GetValue(ipArg)!;
            var ca = parseResult.GetValue(caArg)!;
            var caPwd = parseResult.GetValue(caPassArg)!;
            var dir = parseResult.GetValue(dirArg)!;
            Common.EnsureDirectoryExists(dir);
            X509Certificate2 cert = Cryptography.buildSelfSignedServerCertificate(name, pwd, ip, ca, caPwd);
            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            byte[] data = cert.Export(X509ContentType.Pfx, pwd);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, data);
            Console.WriteLine("Certificate exported to " + path);
        });
        return cmd;
    }
}
