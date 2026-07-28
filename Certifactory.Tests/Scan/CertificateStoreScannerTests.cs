// Soverance Certifactory
// Scott McCutchen
// Enterprise Applications Architect - Soverance Studios
// scott.mccutchen@soverance.com

using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Soverance.Certifactory.Pq;
using Soverance.Certifactory.Scan;
using Xunit;

namespace Certifactory.Tests.Scan;

public class CertificateStoreScannerTests
{
    [Fact]
    public void Scans_a_certificate_added_to_a_temp_currentuser_store()
    {
        // Windows-only: exercises the X509Store path. Skips elsewhere.
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        var signer = SignerFactory.Create(KnownAlgorithms.Rsa4096);
        signer.GenerateKeyPair();
        var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
            CertificatePurpose.RootCa, "store-scan-test", "Pass", signer,
            ServerIp: null, EmailAddress: null, Issuer: null));

        const string tempStoreName = "CertifactoryScanTest";
        using (var store = new X509Store(tempStoreName, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            store.Close();
        }
        try
        {
            // Use the string-named-store overload via a dedicated helper:
            var result = CertificateStoreScanner.ScanNamedStore(StoreLocation.CurrentUser, tempStoreName);
            result.Certificates.Should().Contain(c => c.Cert.SubjectDN.ToString().Contains("store-scan-test"));
        }
        finally
        {
            using var store = new X509Store(tempStoreName, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            var found = store.Certificates.Find(X509FindType.FindBySubjectName, "store-scan-test", false);
            foreach (var c in found) store.Remove(c);
            store.Close();
        }
    }
}
