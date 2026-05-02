// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory.Commands;

using System.CommandLine;

public static class MiscCommands
{
    public static Command BuildVersionCommand()
    {
        var cmd = new Command("version", "Print Certifactory version.");
        cmd.SetAction(_ =>
        {
            Console.WriteLine("Certifactory Version " + Common.GetAssemblyVersion());
        });
        return cmd;
    }

    public static Command BuildTestPfxCommand()
    {
        var pfxArg = new Argument<string>("pfx") { Description = "Absolute path to a PFX certificate bundle." };
        var passwordArg = new Argument<string>("password") { Description = "Password to test against the PFX." };

        var cmd = new Command("testpfx", "Test a PFX password and display certificate details.");
        cmd.Add(pfxArg);
        cmd.Add(passwordArg);
        cmd.SetAction(parseResult =>
        {
            var pfx = parseResult.GetValue(pfxArg)!;
            var pwd = parseResult.GetValue(passwordArg)!;
            Cryptography.testPfxPassword(pfx, pwd);
        });
        return cmd;
    }

    public static Command BuildExportCommand()
    {
        var pfxArg = new Argument<string>("pfx") { Description = "Absolute path to a PFX certificate bundle." };
        var passwordArg = new Argument<string>("password") { Description = "Password used to secure the PFX bundle." };
        var dirArg = new Argument<string>("exportDirectory") { Description = "Directory where PEM files will be written." };

        var cmd = new Command("export", "Export PFX as PEM-encoded files for Linux.");
        cmd.Add(pfxArg);
        cmd.Add(passwordArg);
        cmd.Add(dirArg);
        cmd.SetAction(parseResult =>
        {
            var pfx = parseResult.GetValue(pfxArg)!;
            var pwd = parseResult.GetValue(passwordArg)!;
            var dir = parseResult.GetValue(dirArg)!;
            Common.EnsureDirectoryExists(dir);
            Cryptography.exportCertificatePem(pfx, pwd, dir);
            Console.WriteLine("PEM formatted certificates exported to " + dir);
        });
        return cmd;
    }

    public static Command BuildSshCommand()
    {
        var keyArg = new Argument<string>("keyName") { Description = "Name for the output key files." };
        var commentArg = new Argument<string>("comment") { Description = "Comment embedded in the public key." };
        var dirArg = new Argument<string>("exportDirectory") { Description = "Directory where keys will be written." };

        var cmd = new Command("ssh", "Generate a 4096-bit RSA SSH keypair.");
        cmd.Add(keyArg);
        cmd.Add(commentArg);
        cmd.Add(dirArg);
        cmd.SetAction(parseResult =>
        {
            var keyName = parseResult.GetValue(keyArg)!;
            var comment = parseResult.GetValue(commentArg)!;
            var dir = parseResult.GetValue(dirArg)!;
            Common.EnsureDirectoryExists(dir);
            Cryptography.generateSshKeyPair(keyName, comment, dir);
        });
        return cmd;
    }

    public static Command BuildGpgCommand()
    {
        var keyArg = new Argument<string>("keyName") { Description = "Name for the output key files." };
        var userArg = new Argument<string>("userName") { Description = "Real name for the GPG User ID." };
        var emailArg = new Argument<string>("email") { Description = "Email for the GPG User ID." };
        var passArg = new Argument<string>("passphrase") { Description = "Passphrase to protect the private key." };
        var dirArg = new Argument<string>("exportDirectory") { Description = "Directory where keys will be written." };

        var cmd = new Command("gpg", "Generate a 4096-bit RSA GPG keypair for commit signing.");
        cmd.Add(keyArg);
        cmd.Add(userArg);
        cmd.Add(emailArg);
        cmd.Add(passArg);
        cmd.Add(dirArg);
        cmd.SetAction(parseResult =>
        {
            var keyName = parseResult.GetValue(keyArg)!;
            var user = parseResult.GetValue(userArg)!;
            var email = parseResult.GetValue(emailArg)!;
            var passphrase = parseResult.GetValue(passArg)!;
            var dir = parseResult.GetValue(dirArg)!;
            Common.EnsureDirectoryExists(dir);
            Cryptography.generateGpgKeyPair(keyName, user, email, passphrase, dir);
        });
        return cmd;
    }
}
