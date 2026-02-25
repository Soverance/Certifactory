// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory;

using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class Cryptography
{
    public static X509Certificate2 buildSelfSignedSmimeCertificate(string certificateName, string certificatePassword, string emailAddress, string rootCAPfx, string rootCAPassword)
    {
        // worth looking here, but seems to require on-prem AD CA:  https://docs.microsoft.com/en-us/mem/intune/protect/certificates-s-mime-encryption-sign
        // check this doc for s/mime cert config details:  https://docs.microsoft.com/en-us/archive/blogs/pki/outlook-smime-certificate-selection
        // NOTE: S/MIME configuration is complicated, and worse, you'd really want to use a public CA (such as DigiCert) to ensure maximum compatibility with all recipients
        // NOTE: so even though this method is functional, it really works best if you only send S/MIME email within your organization (where recipients would have the private CA certificate installed on their devices as a trusted root CA)
        // That being said, I recommend using KeyTalk to supply S/MIME certificates and configuration, since it will be significantly easier as your organization grows

        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddEmailAddress(emailAddress);
        sanBuilder.AddUserPrincipalName(emailAddress);

        X500DistinguishedName distinguishedName = new($"CN={certificateName},C=US,ST=Georgia,L=Atlanta,O=Soverance Studios,OU=Information");

        using RSA rsa = RSA.Create(4096);
        var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.DigitalSignature, false));

        OidCollection keyCollection = new()
        {
            new Oid("1.3.6.1.4.1.311.10.3.12"),  // Document Signing
            new Oid("1.3.6.1.5.5.7.3.4")  // Secure Email
        };

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(keyCollection, false));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        request.CertificateExtensions.Add(sanBuilder.Build());

        X509Certificate2 rootCA = new X509Certificate2(rootCAPfx, rootCAPassword, X509KeyStorageFlags.MachineKeySet);

        var certificate = request.Create(rootCA, new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)), Common.GetRandomByteArray(10));

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            certificate.FriendlyName = certificateName;
        }

        using X509Certificate2 exportedCert = certificate.CopyWithPrivateKey(rsa);
        return new X509Certificate2(exportedCert.Export(X509ContentType.Pfx, certificatePassword), certificatePassword, X509KeyStorageFlags.Exportable);
    }

    public static X509Certificate2 buildSelfSignedServerCertificate(string certificateName, string certificatePassword, string serverIP, string rootCAPfx, string rootCAPassword)
    {
        SubjectAlternativeNameBuilder sanBuilder = new();

        sanBuilder.AddDnsName(certificateName);

        if (serverIP != null)
        {
            if (serverIP != "")
            {
                sanBuilder.AddIpAddress(IPAddress.Parse(serverIP));
            }                
        }

        // NOTE: you can create certificates that support localhost or loopback addresses like so:
        //sanBuilder.AddIpAddress(IPAddress.Loopback);
        //sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
        //sanBuilder.AddDnsName("localhost");            
        //sanBuilder.AddDnsName(Environment.MachineName);

        X500DistinguishedName distinguishedName = new($"CN={certificateName}");

        using RSA rsa = RSA.Create(4096);
        var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));

        OidCollection keyCollection = new()
        {
            new Oid("1.3.6.1.5.5.7.3.2"),  // Client Authentication
            new Oid("1.3.6.1.5.5.7.3.1"),  // Server Authentication
        };

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(keyCollection, false));

        request.CertificateExtensions.Add(sanBuilder.Build());

        X509Certificate2 rootCA = new X509Certificate2(rootCAPfx, rootCAPassword, X509KeyStorageFlags.MachineKeySet);

        // while most operating systems are less restrictive, iOS is super annoying about trusting longer expiration lengths.
        // i.e. it doesn't trust anything over 1 year (more secure, obviously)
        // https://support.apple.com/en-us/102028 updated doc for iOS 16
        // https://support.apple.com/en-us/HT210176 old doc for iOS 13
        var certificate = request.Create(rootCA, new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(396)), Common.GetRandomByteArray(10));

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            certificate.FriendlyName = certificateName;
        }

        using X509Certificate2 exportedCert = certificate.CopyWithPrivateKey(rsa);
        return new X509Certificate2(exportedCert.Export(X509ContentType.Pfx, certificatePassword), certificatePassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    public static X509Certificate2 buildRootCACertificate(string certificateName, string certificatePassword)
    {
        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddDnsName(certificateName);

        X500DistinguishedName distinguishedName = new($"CN={certificateName}");

        using RSA rsa = RSA.Create(4096);
        var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, false));

        OidCollection keyCollection = new()
        {
            new Oid("1.3.6.1.5.5.7.3.1"),  // server certificate
            new Oid("1.3.6.1.5.5.7.3.2"),  // client certificate
            new Oid("1.3.6.1.4.1.311.10.3.12"),  // Document Signing
            new Oid("1.3.6.1.5.5.7.3.3"),  // code signing
            new Oid("1.3.6.1.5.5.7.3.4")  // email protection
        };

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(keyCollection, false));

        request.CertificateExtensions.Add(sanBuilder.Build());

        var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(7300)));  // 20 years

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            certificate.FriendlyName = certificateName;
        }

        return new X509Certificate2(certificate.Export(X509ContentType.Pfx, certificatePassword), certificatePassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    public static bool testPfxPassword(string certificatePfx, string certificatePassword)
    {
        try
        {
            X509Certificate2 cert = new X509Certificate2(certificatePfx, certificatePassword, X509KeyStorageFlags.MachineKeySet);
            Console.WriteLine("Password is correct.");
            Console.WriteLine("Subject = " + cert.Subject);
            Console.WriteLine("Thumbprint = " + cert.Thumbprint);
            Console.WriteLine("Issuer = " + cert.Issuer);
            Console.WriteLine("Not Before = " + cert.NotBefore);
            Console.WriteLine("Not After = " + cert.NotAfter);
            return true;
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Password is incorrect, or the PFX file is invalid.");
            return false;
        }
    }

    public static void exportCertificatePem(string certificatePfx, string certificatePassword, string exportPath)
    {
        X509Certificate2 cert = new X509Certificate2(certificatePfx, certificatePassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

        string publicKeyString = cert.ExportCertificatePem();
        RSA privateKeyRSA = cert.GetRSAPrivateKey()!;
        string privateKeyString = privateKeyRSA.ExportRSAPrivateKeyPem();

        byte[] publicKey = Encoding.ASCII.GetBytes(publicKeyString);
        byte[] privateKey = Encoding.ASCII.GetBytes(privateKeyString);

        string certificateName = System.IO.Path.GetFileNameWithoutExtension(certificatePfx);
        string publicCertName = certificateName + ".cer";
        string publicKeyName = certificateName + ".crt.pem";
        string privateKeyName = certificateName + ".key.pem";

        string publicCertExportPath = Path.Combine(exportPath, publicCertName);
        string publicExportPath = Path.Combine(exportPath, publicKeyName);
        string privateExportPath = Path.Combine(exportPath, privateKeyName);

        System.IO.File.WriteAllBytes(publicCertExportPath, publicKey);
        System.IO.File.WriteAllBytes(publicExportPath, publicKey);
        System.IO.File.WriteAllBytes(privateExportPath, privateKey);
    }

    public static void generateSshKeyPair(string keyName, string comment, string exportPath)
    {
        using RSA rsa = RSA.Create(4096);

        // export private key as PKCS#1 PEM (universally accepted by OpenSSH)
        string privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        // build the SSH public key in OpenSSH format: ssh-rsa <base64> <comment>
        RSAParameters rsaParams = rsa.ExportParameters(false);
        byte[] sshPublicKeyBlob = BuildSshPublicKeyBlob(rsaParams);
        string publicKeyBase64 = Convert.ToBase64String(sshPublicKeyBlob);
        string publicKeyString = $"ssh-rsa {publicKeyBase64} {comment}";

        // write files
        string privateKeyPath = Path.Combine(exportPath, keyName);
        string publicKeyPath = Path.Combine(exportPath, keyName + ".pub");

        System.IO.File.WriteAllText(privateKeyPath, privateKeyPem);
        System.IO.File.WriteAllText(publicKeyPath, publicKeyString + "\n");

        Console.WriteLine("SSH keypair generated successfully.");
        Console.WriteLine("Private key exported to " + privateKeyPath);
        Console.WriteLine("Public key exported to " + publicKeyPath);
        Console.WriteLine("NOTE: On Linux, set permissions on the private key with: chmod 600 " + privateKeyPath);
    }

    private static byte[] BuildSshPublicKeyBlob(RSAParameters rsaParams)
    {
        // SSH public key blob format (RFC 4253):
        // string "ssh-rsa"
        // mpint  e (exponent)
        // mpint  n (modulus)
        using MemoryStream stream = new();
        WriteSshString(stream, "ssh-rsa");
        WriteSshBigInt(stream, rsaParams.Exponent!);
        WriteSshBigInt(stream, rsaParams.Modulus!);
        return stream.ToArray();
    }

    private static void WriteSshBytes(MemoryStream stream, byte[] data)
    {
        // write 4-byte big-endian length prefix followed by data
        byte[] length = BitConverter.GetBytes(data.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(length);
        stream.Write(length, 0, 4);
        stream.Write(data, 0, data.Length);
    }

    private static void WriteSshString(MemoryStream stream, string value)
    {
        WriteSshBytes(stream, Encoding.ASCII.GetBytes(value));
    }

    private static void WriteSshBigInt(MemoryStream stream, byte[] bigInt)
    {
        // SSH mpint format requires a leading zero byte if the MSB is set,
        // to distinguish positive integers from negative ones
        if (bigInt[0] >= 0x80)
        {
            byte[] padded = new byte[bigInt.Length + 1];
            padded[0] = 0;
            Array.Copy(bigInt, 0, padded, 1, bigInt.Length);
            WriteSshBytes(stream, padded);
        }
        else
        {
            WriteSshBytes(stream, bigInt);
        }
    }
}
