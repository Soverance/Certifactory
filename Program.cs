// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory;

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main(string[] args)
    {
        // begin parsing arguments
        // there is almost certainly a better way to do this...
        if (args.Length <= 0) //Checking the Length helps avoid NullReferenceException at args[0]
        {
            Console.WriteLine("Soverance Studios - Certifactory certificate generation utility.");
            Console.WriteLine("Console Redirected: " + Console.IsOutputRedirected);
            Console.WriteLine("No parameters specified, exiting...");
        }
        else
        {
            try
            {
                switch (args[0])
                {
                    case "-version":
                        string version2 = "Certifactory Version " + Common.GetAssemblyVersion();
                        Console.WriteLine(version2);
                        break;
                    case "version":
                        string version3 = "Certifactory Version " + Common.GetAssemblyVersion();
                        Console.WriteLine(version3);
                        break;
                    case "ca":
                        // args[1] = cert name
                        // args[2] = cert password
                        // args[3] = export directory
                        X509Certificate2 ca_cert = Cryptography.buildRootCACertificate(args[1], args[2]);
                        Console.WriteLine("Certificate Thumbprint = " + ca_cert.Thumbprint);
                        byte[] ca_certData = ca_cert.Export(X509ContentType.Pfx, args[2]);
                        string ca_fullName = args[1] + ".pfx";
                        string ca_exportPath = Path.Combine(args[3], ca_fullName);
                        System.IO.File.WriteAllBytes(ca_exportPath, ca_certData);
                        Console.WriteLine("Certificate exported to " + ca_exportPath);
                        break;
                    case "server":
                        // args[1] = cert name
                        // args[2] = cert password
                        // args[3] = server IP                        
                        // args[4] = root CA PFX path
                        // args[5] = root CA PFX password
                        // args[6] = export directory
                        X509Certificate2 cert = Cryptography.buildSelfSignedServerCertificate(args[1], args[2], args[3], args[4], args[5]);
                        Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
                        byte[] certData = cert.Export(X509ContentType.Pfx, args[2]);
                        string fullName = args[1] + ".pfx";
                        string exportPath = Path.Combine(args[6], fullName);
                        System.IO.File.WriteAllBytes(exportPath, certData);
                        Console.WriteLine("Certificate exported to " + exportPath);
                        break;
                    case "smime":
                        // args[1] = cert name
                        // args[2] = cert password
                        // args[3] = email address                       
                        // args[4] = root CA PFX path
                        // args[5] = root CA PFX password
                        // args[6] = export directory
                        X509Certificate2 email_cert = Cryptography.buildSelfSignedSmimeCertificate(args[1], args[2], args[3], args[4], args[5]);
                        Console.WriteLine("Certificate Thumbprint = " + email_cert.Thumbprint);
                        byte[] email_certData = email_cert.Export(X509ContentType.Pfx, args[2]);
                        string email_fullName = args[1] + ".pfx";
                        string email_exportPath = Path.Combine(args[6], email_fullName);
                        System.IO.File.WriteAllBytes(email_exportPath, email_certData);
                        Console.WriteLine("Certificate exported to " + email_exportPath);
                        break;
                    case "export":
                        // args[1] = cert pfx path
                        // args[2] = cert password
                        // args[3] = export directory
                        Cryptography.exportCertificatePem(args[1], args[2], args[3]);
                        Console.WriteLine("PEM formatted certificates exported to " + args[3]);
                        break;
                    default:
                        Console.WriteLine("An invalid parameter was specified at position 1.");
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw;
            }
        }
    }
}