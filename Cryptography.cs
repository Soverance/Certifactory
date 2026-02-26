// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

namespace Soverance.Certifactory;

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

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

    public static void generateGpgKeyPair(string keyName, string userName, string email, string passphrase, string exportPath)
    {
        Console.WriteLine("Generating GPG keypair...");

        // generate two RSA 4096-bit key pairs (master + encryption subkey)
        var keyGenParams = new RsaKeyGenerationParameters(
            BigInteger.ValueOf(0x10001), new SecureRandom(), 4096, 12);

        var keyPairGen = new RsaKeyPairGenerator();
        keyPairGen.Init(keyGenParams);

        AsymmetricCipherKeyPair masterKeyPair = keyPairGen.GenerateKeyPair();
        AsymmetricCipherKeyPair encKeyPair = keyPairGen.GenerateKeyPair();

        // build master key with sign + certify capabilities
        PgpKeyPair pgpMasterKeyPair = new PgpKeyPair(
            PublicKeyAlgorithmTag.RsaGeneral, masterKeyPair, DateTime.UtcNow);

        PgpKeyPair pgpEncKeyPair = new PgpKeyPair(
            PublicKeyAlgorithmTag.RsaGeneral, encKeyPair, DateTime.UtcNow);

        // master key signature subpackets
        PgpSignatureSubpacketGenerator masterSubpacketGen = new PgpSignatureSubpacketGenerator();
        masterSubpacketGen.SetKeyFlags(false, PgpKeyFlags.CanSign | PgpKeyFlags.CanCertify);
        masterSubpacketGen.SetPreferredSymmetricAlgorithms(false, new int[]
        {
            (int)SymmetricKeyAlgorithmTag.Aes256,
            (int)SymmetricKeyAlgorithmTag.Aes192,
            (int)SymmetricKeyAlgorithmTag.Aes128
        });
        masterSubpacketGen.SetPreferredHashAlgorithms(false, new int[]
        {
            (int)HashAlgorithmTag.Sha256,
            (int)HashAlgorithmTag.Sha384,
            (int)HashAlgorithmTag.Sha512,
            (int)HashAlgorithmTag.Sha224,
            (int)HashAlgorithmTag.Sha1
        });

        // encryption subkey subpackets
        PgpSignatureSubpacketGenerator encSubpacketGen = new PgpSignatureSubpacketGenerator();
        encSubpacketGen.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);

        // build the key ring generator
        string identity = $"{userName} <{email}>";
        PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
            PgpSignature.DefaultCertification,
            pgpMasterKeyPair,
            identity,
            SymmetricKeyAlgorithmTag.Aes256,
            passphrase.ToCharArray(),
            true,
            masterSubpacketGen.Generate(),
            null,
            new SecureRandom());

        keyRingGen.AddSubKey(pgpEncKeyPair, encSubpacketGen.Generate(), null);

        // export public key ring
        string publicKeyPath = Path.Combine(exportPath, keyName + ".gpg.pub");
        using (FileStream pubStream = new FileStream(publicKeyPath, FileMode.Create))
        using (ArmoredOutputStream armoredPub = new ArmoredOutputStream(pubStream))
        {
            keyRingGen.GeneratePublicKeyRing().Encode(armoredPub);
        }

        // export secret key ring
        string secretKeyPath = Path.Combine(exportPath, keyName + ".gpg.sec");
        using (FileStream secStream = new FileStream(secretKeyPath, FileMode.Create))
        using (ArmoredOutputStream armoredSec = new ArmoredOutputStream(secStream))
        {
            keyRingGen.GenerateSecretKeyRing().Encode(armoredSec);
        }

        // extract and display the key ID
        PgpPublicKeyRing publicKeyRing = keyRingGen.GeneratePublicKeyRing();
        PgpPublicKey masterPublicKey = publicKeyRing.GetPublicKey();
        string keyId = masterPublicKey.KeyId.ToString("X");

        Console.WriteLine("GPG keypair generated successfully.");
        Console.WriteLine("Key ID: " + keyId);
        Console.WriteLine("Public key exported to " + publicKeyPath);
        Console.WriteLine("Secret key exported to " + secretKeyPath);

        // attempt auto-import and full configuration via system gpg
        string gpgPath = FindGpgPath();

        if (gpgPath != null)
        {
            Console.WriteLine($"GPG found at: {gpgPath}");
            Console.WriteLine("Attempting to import secret key...");

            // 1. Import the secret key
            bool importSuccess = false;
            try
            {
                var importProcess = new Process();
                importProcess.StartInfo.FileName = gpgPath;
                importProcess.StartInfo.Arguments = $"--import \"{secretKeyPath}\"";
                importProcess.StartInfo.RedirectStandardOutput = true;
                importProcess.StartInfo.RedirectStandardError = true;
                importProcess.StartInfo.UseShellExecute = false;
                importProcess.StartInfo.CreateNoWindow = true;
                importProcess.Start();
                string importOutput = importProcess.StandardError.ReadToEnd();
                importProcess.WaitForExit();

                if (importProcess.ExitCode == 0)
                {
                    Console.WriteLine("Secret key imported successfully into GPG keyring.");
                    importSuccess = true;
                }
                else
                {
                    Console.WriteLine("GPG import failed: " + importOutput);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("GPG import error: " + ex.Message);
            }

            if (importSuccess)
            {
                // 2. Set ownertrust to ultimate for our key
                SetKeyTrustUltimate(gpgPath, keyId);

                // 3. Configure gpg-agent for long-lived passphrase caching
                ConfigureGpgAgent(gpgPath);

                // 4. Pre-seed the passphrase into gpg-agent so user is never prompted
                PresetPassphrase(gpgPath, keyId, passphrase);

                // 5. Configure git for commit signing
                ConfigureGitSigning(gpgPath, keyId);
            }
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("GPG was not found on this system.");
            Console.WriteLine("To import the key manually, install GPG and run:");
            Console.WriteLine($"  gpg --import \"{secretKeyPath}\"");
            Console.WriteLine();
            Console.WriteLine("Then configure git for commit signing:");
            Console.WriteLine($"  git config --global user.signingkey {keyId}");
            Console.WriteLine("  git config --global commit.gpgsign true");
        }

        Console.WriteLine();
        Console.WriteLine("To add the public key to GitHub, copy the contents of:");
        Console.WriteLine($"  {publicKeyPath}");
        Console.WriteLine("Then go to GitHub > Settings > SSH and GPG keys > New GPG key");
    }

    /// <summary>
    /// Finds the full path to gpg.exe by running "gpg --version".
    /// Returns the absolute path if found, null otherwise.
    /// </summary>
    private static string? FindGpgPath()
    {
        try
        {
            // first try running gpg directly to confirm it's available
            var process = new Process();
            process.StartInfo.FileName = "gpg";
            process.StartInfo.Arguments = "--version";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            process.WaitForExit();

            if (process.ExitCode != 0)
                return null;

            // resolve full path using where (Windows) or which (Unix)
            string whichCommand = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "where" : "which";
            var whereProcess = new Process();
            whereProcess.StartInfo.FileName = whichCommand;
            whereProcess.StartInfo.Arguments = "gpg";
            whereProcess.StartInfo.RedirectStandardOutput = true;
            whereProcess.StartInfo.RedirectStandardError = true;
            whereProcess.StartInfo.UseShellExecute = false;
            whereProcess.StartInfo.CreateNoWindow = true;
            whereProcess.Start();
            string output = whereProcess.StandardOutput.ReadToEnd();
            whereProcess.WaitForExit();

            if (whereProcess.ExitCode == 0)
            {
                // "where" on Windows may return multiple lines; take the first
                string firstLine = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
                if (!string.IsNullOrWhiteSpace(firstLine))
                    return firstLine.Trim();
            }

            // fallback: gpg is in PATH but we couldn't resolve the full path
            return "gpg";
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Sets the ownertrust of the given key to ultimate so GPG
    /// does not display trust warnings when signing.
    /// </summary>
    private static void SetKeyTrustUltimate(string gpgPath, string keyId)
    {
        try
        {
            // format: <fingerprint>:6:\n  (6 = ultimate trust)
            var process = new Process();
            process.StartInfo.FileName = gpgPath;
            process.StartInfo.Arguments = "--import-ownertrust";
            process.StartInfo.RedirectStandardInput = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            process.StandardInput.WriteLine($"{keyId}:6:");
            process.StandardInput.Close();
            process.WaitForExit();

            if (process.ExitCode == 0)
            {
                Console.WriteLine("Key trust set to ultimate.");
            }
            else
            {
                string err = process.StandardError.ReadToEnd();
                Console.WriteLine("Warning: could not set key trust: " + err);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Warning: could not set key trust: " + ex.Message);
        }
    }

    /// <summary>
    /// Configures gpg-agent.conf with long-lived passphrase caching
    /// and allow-preset-passphrase so the passphrase can be pre-seeded.
    /// </summary>
    private static void ConfigureGpgAgent(string gpgPath)
    {
        try
        {
            // determine the GnuPG home directory
            string gnupgHome = GetGnupgHome(gpgPath);
            if (string.IsNullOrEmpty(gnupgHome))
            {
                Console.WriteLine("Warning: could not determine GnuPG home directory.");
                return;
            }

            string agentConfPath = Path.Combine(gnupgHome, "gpg-agent.conf");
            string existingContent = File.Exists(agentConfPath) ? File.ReadAllText(agentConfPath) : "";

            // settings we want to ensure are present
            var requiredSettings = new Dictionary<string, string>
            {
                { "default-cache-ttl", "34560000" },
                { "max-cache-ttl", "34560000" },
                { "allow-preset-passphrase", "" }
            };

            string updatedContent = existingContent;
            bool modified = false;

            foreach (var setting in requiredSettings)
            {
                string key = setting.Key;
                string value = setting.Value;
                string fullLine = string.IsNullOrEmpty(value) ? key : $"{key} {value}";

                // check if the setting already exists (as a non-comment line)
                bool found = false;
                foreach (string line in updatedContent.Split('\n'))
                {
                    string trimmed = line.Trim();
                    if (!trimmed.StartsWith("#") && trimmed.StartsWith(key))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    if (updatedContent.Length > 0 && !updatedContent.EndsWith("\n"))
                        updatedContent += "\n";
                    updatedContent += fullLine + "\n";
                    modified = true;
                }
            }

            if (modified)
            {
                File.WriteAllText(agentConfPath, updatedContent);
                Console.WriteLine("gpg-agent.conf updated with long-lived passphrase caching.");

                // reload the agent so the new config takes effect
                ReloadGpgAgent(gpgPath);
            }
            else
            {
                Console.WriteLine("gpg-agent.conf already configured for passphrase caching.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Warning: could not configure gpg-agent: " + ex.Message);
        }
    }

    /// <summary>
    /// Pre-seeds the passphrase into gpg-agent using gpg-preset-passphrase,
    /// so the user is never prompted for the passphrase during commit signing.
    /// </summary>
    private static void PresetPassphrase(string gpgPath, string keyId, string passphrase)
    {
        try
        {
            // get the keygrip for the signing key
            string? keygrip = GetKeygrip(gpgPath, keyId);
            if (keygrip == null)
            {
                Console.WriteLine("Warning: could not determine keygrip for passphrase preset.");
                return;
            }

            // find gpg-preset-passphrase in the same directory as gpg,
            // or in the libexec directory
            string? presetPath = FindPresetPassphraseTool(gpgPath);
            if (presetPath == null)
            {
                Console.WriteLine("Warning: gpg-preset-passphrase tool not found. You may be prompted for the passphrase on first use.");
                return;
            }

            // convert passphrase to hex encoding as required by gpg-preset-passphrase
            string passphraseHex = BitConverter.ToString(Encoding.UTF8.GetBytes(passphrase)).Replace("-", "");

            var process = new Process();
            process.StartInfo.FileName = presetPath;
            process.StartInfo.Arguments = $"--preset {keygrip}";
            process.StartInfo.RedirectStandardInput = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            process.StandardInput.Write(passphraseHex);
            process.StandardInput.Close();
            process.WaitForExit();

            if (process.ExitCode == 0)
            {
                Console.WriteLine("Passphrase pre-seeded into gpg-agent. You will not be prompted for the passphrase.");
            }
            else
            {
                string err = process.StandardError.ReadToEnd();
                Console.WriteLine("Warning: could not preset passphrase: " + err);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Warning: could not preset passphrase: " + ex.Message);
        }
    }

    /// <summary>
    /// Configures git globally for GPG commit signing, including
    /// setting gpg.program to the resolved gpg path.
    /// </summary>
    private static void ConfigureGitSigning(string gpgPath, string keyId)
    {
        try
        {
            RunGitConfig("user.signingkey", keyId);
            RunGitConfig("commit.gpgsign", "true");
            RunGitConfig("gpg.program", gpgPath);

            Console.WriteLine("Git configured for GPG commit signing:");
            Console.WriteLine($"  user.signingkey = {keyId}");
            Console.WriteLine($"  commit.gpgsign = true");
            Console.WriteLine($"  gpg.program = {gpgPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Warning: could not configure git: " + ex.Message);
            Console.WriteLine("You can configure git manually:");
            Console.WriteLine($"  git config --global user.signingkey {keyId}");
            Console.WriteLine("  git config --global commit.gpgsign true");
            Console.WriteLine($"  git config --global gpg.program \"{gpgPath}\"");
        }
    }

    private static void RunGitConfig(string key, string value)
    {
        var process = new Process();
        process.StartInfo.FileName = "git";
        process.StartInfo.Arguments = $"config --global {key} \"{value}\"";
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;
        process.Start();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            string err = process.StandardError.ReadToEnd();
            throw new Exception($"git config {key} failed: {err}");
        }
    }

    /// <summary>
    /// Returns the GnuPG home directory by parsing "gpg --version" output
    /// or falling back to the GNUPGHOME env var / default location.
    /// </summary>
    private static string GetGnupgHome(string gpgPath)
    {
        try
        {
            var process = new Process();
            process.StartInfo.FileName = gpgPath;
            process.StartInfo.Arguments = "--version";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            // look for "Home: <path>" in the output
            foreach (string line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("Home:"))
                {
                    return trimmed.Substring("Home:".Length).Trim();
                }
            }
        }
        catch { }

        // fallback to GNUPGHOME or default
        string? envHome = Environment.GetEnvironmentVariable("GNUPGHOME");
        if (!string.IsNullOrEmpty(envHome))
            return envHome;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "gnupg");

        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".gnupg");
    }

    /// <summary>
    /// Reloads gpg-agent so config changes take effect.
    /// </summary>
    private static void ReloadGpgAgent(string gpgPath)
    {
        try
        {
            // use gpg-connect-agent to reload
            string gpgDir = Path.GetDirectoryName(gpgPath) ?? "";
            string connectAgent = Path.Combine(gpgDir, "gpg-connect-agent");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                connectAgent += ".exe";

            if (!File.Exists(connectAgent))
            {
                // try just the name on PATH
                connectAgent = "gpg-connect-agent";
            }

            var process = new Process();
            process.StartInfo.FileName = connectAgent;
            process.StartInfo.Arguments = "reloadagent /bye";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            process.WaitForExit();
        }
        catch { }
    }

    /// <summary>
    /// Gets the keygrip for a given key ID by parsing "gpg --list-keys --with-keygrip".
    /// </summary>
    private static string? GetKeygrip(string gpgPath, string keyId)
    {
        try
        {
            var process = new Process();
            process.StartInfo.FileName = gpgPath;
            process.StartInfo.Arguments = $"--list-keys --with-keygrip {keyId}";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            // the first "Keygrip = <hex>" line corresponds to the master signing key
            foreach (string line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("Keygrip = "))
                {
                    return trimmed.Substring("Keygrip = ".Length).Trim();
                }
            }
        }
        catch { }

        return null;
    }

    /// <summary>
    /// Locates the gpg-preset-passphrase tool, which may be in the same
    /// directory as gpg or in a libexec subdirectory.
    /// </summary>
    private static string? FindPresetPassphraseTool(string gpgPath)
    {
        string gpgDir = Path.GetDirectoryName(gpgPath) ?? "";
        string exeName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "gpg-preset-passphrase.exe"
            : "gpg-preset-passphrase";

        // check same directory as gpg
        string sameDirPath = Path.Combine(gpgDir, exeName);
        if (File.Exists(sameDirPath))
            return sameDirPath;

        // check libexec subdirectory (common on some installations)
        string libexecPath = Path.Combine(gpgDir, "..", "libexec", exeName);
        if (File.Exists(libexecPath))
            return libexecPath;

        // check Gpg4win typical location
        string gpg4winLibexec = Path.Combine(gpgDir, "..", "bin", exeName);
        if (File.Exists(gpg4winLibexec))
            return gpg4winLibexec;

        // try on PATH as last resort
        try
        {
            string whichCommand = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "where" : "which";
            var process = new Process();
            process.StartInfo.FileName = whichCommand;
            process.StartInfo.Arguments = exeName.Replace(".exe", "");
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode == 0)
            {
                string firstLine = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
                if (!string.IsNullOrWhiteSpace(firstLine))
                    return firstLine.Trim();
            }
        }
        catch { }

        return null;
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
