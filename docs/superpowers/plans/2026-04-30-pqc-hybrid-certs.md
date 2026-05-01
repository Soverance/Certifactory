# Post-Quantum & Hybrid Certificate Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `--algorithm` flag to the `ca`, `server`, and `smime` commands that selects between `rsa-4096` (default), `ml-dsa-65`, `slh-dsa-256s`, and `hybrid` (RSA-4096 + ML-DSA-65 with backward-compatible alt-signature extensions).

**Architecture:** A new `IPqSigner` abstraction owns keypair generation and signing for each algorithm; a single `CertificateBuilder` produces certs parameterized by purpose (CA / server / S/MIME) and signer. Hybrid uses the X.509:2019 alternative-signature extensions (`subjectAltPublicKeyInfo` 2.5.29.72, `altSignatureAlgorithm` 2.5.29.73, `altSignatureValue` 2.5.29.74) so legacy RSA-only verifiers ignore the PQC payload while PQ-aware verifiers can validate the alt chain. All PQC primitives flow through BouncyCastle on net8.0; the `IPqSigner` boundary is designed so a future .NET 10 follow-up can swap to native `System.Security.Cryptography.MLDsa` / `SlhDsa` in one file.

**Tech Stack:** C# / net8.0, `System.CommandLine` (replacing positional parsing), BouncyCastle.Cryptography 2.6.2 (existing), xUnit + FluentAssertions for tests.

---

## File Structure

### New files

| Path | Responsibility |
|---|---|
| `Pq/IPqSigner.cs` | Interface: `string AlgorithmId`, `string SignatureOid`, `AsymmetricCipherKeyPair GenerateKeyPair()`, `byte[] Sign(byte[] tbs)`, `bool Verify(byte[] tbs, byte[] sig, AsymmetricKeyParameter pubKey)`, `ISignatureFactory CreateSignatureFactory()`. |
| `Pq/Signing.cs` | `RsaSigner`, `MlDsaSigner`, `SlhDsaSigner`, `HybridSigner` (composes one classical + one PQ signer), `SignerFactory.Create(string algorithm)`. |
| `Pq/CertificateBuilder.cs` | `CertificateSpec` record (purpose, names, validity, IP, email, signer, issuerCert, issuerSigner). `BuildCertificate(spec)` returns an `X509Certificate2` (the .NET type) with private key bundled, ready to PFX-export. Replaces the three `buildXxx` methods on `Cryptography.cs`. |
| `Pq/HybridExtensions.cs` | `BuildAltExtensions(altSigner, preTbs)` — encodes the three alt-sig extensions; `ExtractPreTbsForAltSig(tbs)` — strips altSignatureValue for verification. Manual TBS construction lives here because BC's `X509V3CertificateGenerator` does not support multi-pass signing. |
| `Pq/PfxExporter.cs` | Bundles a BC `X509Certificate` + private key into a PFX byte array via `Pkcs12StoreBuilder`, then loads as `X509Certificate2`. One static method. |
| `Commands/CaCommand.cs` | `System.CommandLine` subcommand definition for `ca`, with `--algorithm` option. |
| `Commands/ServerCommand.cs` | Subcommand for `server`. |
| `Commands/SmimeCommand.cs` | Subcommand for `smime`. |
| `Commands/MiscCommands.cs` | Subcommands for `testpfx`, `export`, `ssh`, `gpg`, `version` — preserve existing behavior, just rewired through `System.CommandLine`. |
| `Certifactory.Tests/Certifactory.Tests.csproj` | xUnit test project targeting net8.0. |
| `Certifactory.Tests/SigningTests.cs` | Sign/verify roundtrip per algorithm. |
| `Certifactory.Tests/CertificateBuilderTests.cs` | CA generation, server-signed-by-CA chain validation, S/MIME extensions present. One per algorithm. |
| `Certifactory.Tests/HybridExtensionsTests.cs` | Alt-sig extension encoding correctness; legacy RSA verification of hybrid cert; PQ alt-sig verification of hybrid cert. |

### Modified files

| Path | Change |
|---|---|
| `Program.cs` | Replace `switch` block with `System.CommandLine` root command wiring. |
| `Common.cs` | Fix `GetRandomByteArray` to use `RandomNumberGenerator.GetBytes`. Remove `Debug.WriteLine` dead line. |
| `Cryptography.cs` | Remove `buildRootCACertificate`, `buildSelfSignedServerCertificate`, `buildSelfSignedSmimeCertificate`. Keep `testPfxPassword`, `exportCertificatePem`, `generateSshKeyPair`, `generateGpgKeyPair`, and all the gpg helpers — these are unchanged. |
| `Certifactory.csproj` | Add `System.CommandLine` package reference. |
| `Certifactory.sln` | Add the test project. |
| `README.md` | Document `--algorithm` flag and the algorithm comparison table. |
| `docs/ca.md`, `docs/server.md`, `docs/smime.md` | Document `--algorithm` flag with examples. |

---

## Phase 0 — Scaffolding & API verification

### Task 0.1: Add System.CommandLine and create test project

**Files:**
- Modify: `Certifactory.csproj`
- Create: `Certifactory.Tests/Certifactory.Tests.csproj`
- Modify: `Certifactory.sln`

- [ ] **Step 1: Add System.CommandLine to main project**

Edit `Certifactory.csproj`, add inside the existing `<ItemGroup>`:

```xml
<PackageReference Include="System.CommandLine" Version="2.0.0-beta4.22272.1" />
```

(2.0.0-beta4.x is the version that ships in the .NET 8 SDK timeframe; pin explicitly so future SDK changes do not break the plan.)

- [ ] **Step 2: Create test project**

Run:

```bash
dotnet new xunit -n Certifactory.Tests -o Certifactory.Tests --framework net8.0
```

- [ ] **Step 3: Add test project references and packages**

Edit `Certifactory.Tests/Certifactory.Tests.csproj` to include:

```xml
<ItemGroup>
  <PackageReference Include="FluentAssertions" Version="6.12.0" />
  <PackageReference Include="BouncyCastle.Cryptography" Version="2.6.2" />
</ItemGroup>
<ItemGroup>
  <ProjectReference Include="..\Certifactory.csproj" />
</ItemGroup>
```

- [ ] **Step 4: Add test project to solution**

Run from repo root containing `Certifactory.sln`:

```bash
dotnet sln Certifactory.sln add Certifactory.Tests/Certifactory.Tests.csproj
```

- [ ] **Step 5: Verify build**

```bash
dotnet build Certifactory.sln
```

Expected: build succeeds. The test project has the default `UnitTest1.cs` from the template — leave it.

- [ ] **Step 6: Commit**

```bash
git add Certifactory.csproj Certifactory.sln Certifactory.Tests/
git commit -m "chore: add System.CommandLine and test project scaffold"
```

---

### Task 0.2: API verification spike for BouncyCastle PQ namespaces

**Files:**
- Create (temporary): `Certifactory.Tests/PqApiSpike.cs`

Goal: confirm the exact namespaces and class names exposed by `BouncyCastle.Cryptography` 2.6.2 for ML-DSA and SLH-DSA before writing production code against them. The .NET BC port has occasionally lagged the Java BC API — this 5-minute spike prevents 30 minutes of compile-error chasing.

- [ ] **Step 1: Write a spike test**

Create `Certifactory.Tests/PqApiSpike.cs`:

```csharp
using FluentAssertions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Xunit;

namespace Certifactory.Tests;

public class PqApiSpike
{
    [Fact]
    public void MlDsa_keypair_generation_works()
    {
        // try the expected namespace path; if it fails, the test name + exception
        // tell us the right path to use in production code
        var random = new SecureRandom();

        var keyGen = new Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaKeyPairGenerator();
        keyGen.Init(new Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaKeyGenerationParameters(
            random, Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaParameters.ml_dsa_65));
        AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();
        kp.Public.Should().NotBeNull();
        kp.Private.Should().NotBeNull();
    }

    [Fact]
    public void SlhDsa_keypair_generation_works()
    {
        var random = new SecureRandom();

        var keyGen = new Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaKeyPairGenerator();
        keyGen.Init(new Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaKeyGenerationParameters(
            random, Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaParameters.slh_dsa_sha2_256s));
        AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();
        kp.Public.Should().NotBeNull();
    }
}
```

- [ ] **Step 2: Run the spike**

```bash
dotnet test Certifactory.Tests/Certifactory.Tests.csproj --filter "FullyQualifiedName~PqApiSpike"
```

- [ ] **Step 3: Reconcile findings**

If a namespace fails to resolve, search the BC dll for the actual one:

```bash
dotnet tool install -g ilspycmd
ilspycmd ~/.nuget/packages/bouncycastle.cryptography/2.6.2/lib/net6.0/BouncyCastle.Cryptography.dll | grep -E "MLDsa|SlhDsa|MlDsa" | head -40
```

Record the verified namespaces in a code comment at the top of `PqApiSpike.cs`. **All subsequent production code must use these verified namespaces.** If any later task in this plan uses a namespace name that does not match the verified spike, update the task before implementing.

- [ ] **Step 4: Run spike to green**

```bash
dotnet test Certifactory.Tests/Certifactory.Tests.csproj --filter "FullyQualifiedName~PqApiSpike"
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add Certifactory.Tests/PqApiSpike.cs
git commit -m "test: verify BouncyCastle PQ API surface (ML-DSA, SLH-DSA)"
```

The spike file stays in the repo as a permanent canary — if a future BC bump breaks our assumed API, this fails loudly.

---

## Phase 1 — Fix the CSPRNG bug for serial numbers

### Task 1.1: Replace System.Random with RandomNumberGenerator

**Files:**
- Modify: `Common.cs:55-62`
- Test: `Certifactory.Tests/CommonTests.cs` (new)

Reason: `System.Random` is not cryptographically secure. Certificate serial numbers should be unpredictable to prevent collision attacks against the CA's signature.

- [ ] **Step 1: Write the failing test**

Create `Certifactory.Tests/CommonTests.cs`:

```csharp
using FluentAssertions;
using Soverance.Certifactory;
using Xunit;

namespace Certifactory.Tests;

public class CommonTests
{
    [Fact]
    public void GetRandomByteArray_returns_high_entropy_bytes()
    {
        // generate 1000 20-byte arrays. with CSPRNG, no two should collide.
        // with System.Random seeded by time-of-day, rapid successive calls
        // can collide — this test would fail on the old impl in a tight loop.
        var seen = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
        {
            byte[] b = Common.GetRandomByteArray(20);
            string key = Convert.ToHexString(b);
            seen.Add(key).Should().BeTrue("each call should produce unique bytes");
        }
    }

    [Fact]
    public void GetRandomByteArray_returns_requested_length()
    {
        Common.GetRandomByteArray(16).Should().HaveCount(16);
        Common.GetRandomByteArray(32).Should().HaveCount(32);
    }
}
```

- [ ] **Step 2: Run test to verify failure mode (or pass — System.Random rarely collides at 20 bytes, so this test guards against the worst case rather than proving the bug)**

```bash
dotnet test Certifactory.Tests/Certifactory.Tests.csproj --filter "FullyQualifiedName~CommonTests"
```

Note: at 20 bytes, `System.Random` may also pass this test by luck. The fix is still correct; the test guards against degenerate cases and documents intent.

- [ ] **Step 3: Apply the fix**

Edit `Common.cs:55-62`. Replace:

```csharp
public static byte[] GetRandomByteArray(int size)
{
    Random rnd = new();
    byte[] b = new byte[size];
    rnd.NextBytes(b);
    Debug.WriteLine("[DEBUG] BYTE ARRAY = " + b);
    return b;
}
```

with:

```csharp
public static byte[] GetRandomByteArray(int size)
{
    byte[] b = new byte[size];
    System.Security.Cryptography.RandomNumberGenerator.Fill(b);
    return b;
}
```

- [ ] **Step 4: Run tests to verify pass**

```bash
dotnet test Certifactory.Tests/Certifactory.Tests.csproj
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Common.cs Certifactory.Tests/CommonTests.cs
git commit -m "fix: use CSPRNG for certificate serial number entropy"
```

---

## Phase 2 — System.CommandLine refactor (no behavior change)

The goal of this phase is purely structural: every existing command must produce identical output to before. We rewire the parsing only.

### Task 2.1: Build the root command skeleton

**Files:**
- Create: `Commands/MiscCommands.cs`
- Modify: `Program.cs`

- [ ] **Step 1: Build empty subcommand registrations**

Create `Commands/MiscCommands.cs`:

```csharp
namespace Soverance.Certifactory.Commands;

using System.CommandLine;

public static class MiscCommands
{
    public static Command BuildVersionCommand()
    {
        var cmd = new Command("version", "Print Certifactory version.");
        cmd.SetHandler(() =>
        {
            Console.WriteLine("Certifactory Version " + Common.GetAssemblyVersion());
        });
        return cmd;
    }
}
```

- [ ] **Step 2: Replace Program.cs Main**

Replace the entire `Program.cs` with:

```csharp
namespace Soverance.Certifactory;

using System.CommandLine;
using Soverance.Certifactory.Commands;

class Program
{
    static int Main(string[] args)
    {
        var root = new RootCommand("Soverance Studios - Certifactory certificate generation utility.");
        root.AddCommand(MiscCommands.BuildVersionCommand());
        return root.Invoke(args);
    }
}
```

- [ ] **Step 3: Verify version command works**

```bash
dotnet run --project Certifactory.csproj -- version
```

Expected output: `Certifactory Version 1.0.0`

- [ ] **Step 4: Commit**

```bash
git add Program.cs Commands/MiscCommands.cs
git commit -m "refactor: introduce System.CommandLine root command with version"
```

---

### Task 2.2: Wire `testpfx` and `export` (smaller, no algorithm dispatch)

**Files:**
- Modify: `Commands/MiscCommands.cs`
- Modify: `Program.cs`

- [ ] **Step 1: Add `testpfx` subcommand**

Add to `Commands/MiscCommands.cs`:

```csharp
public static Command BuildTestPfxCommand()
{
    var pfxArg = new Argument<string>("pfx", "Absolute path to a PFX certificate bundle.");
    var passwordArg = new Argument<string>("password", "Password to test against the PFX.");

    var cmd = new Command("testpfx", "Test a PFX password and display certificate details.");
    cmd.AddArgument(pfxArg);
    cmd.AddArgument(passwordArg);
    cmd.SetHandler((string pfx, string pwd) =>
    {
        Cryptography.testPfxPassword(pfx, pwd);
    }, pfxArg, passwordArg);
    return cmd;
}

public static Command BuildExportCommand()
{
    var pfxArg = new Argument<string>("pfx", "Absolute path to a PFX certificate bundle.");
    var passwordArg = new Argument<string>("password", "Password used to secure the PFX bundle.");
    var dirArg = new Argument<string>("exportDirectory", "Directory where PEM files will be written.");

    var cmd = new Command("export", "Export PFX as PEM-encoded files for Linux.");
    cmd.AddArgument(pfxArg);
    cmd.AddArgument(passwordArg);
    cmd.AddArgument(dirArg);
    cmd.SetHandler((string pfx, string pwd, string dir) =>
    {
        Common.EnsureDirectoryExists(dir);
        Cryptography.exportCertificatePem(pfx, pwd, dir);
        Console.WriteLine("PEM formatted certificates exported to " + dir);
    }, pfxArg, passwordArg, dirArg);
    return cmd;
}
```

- [ ] **Step 2: Register both in Program.cs**

In `Program.cs` `Main`, add after `BuildVersionCommand`:

```csharp
root.AddCommand(MiscCommands.BuildTestPfxCommand());
root.AddCommand(MiscCommands.BuildExportCommand());
```

- [ ] **Step 3: Smoke test**

```bash
dotnet run --project Certifactory.csproj -- testpfx --help
dotnet run --project Certifactory.csproj -- export --help
```

Expected: help text shows the three positional args correctly.

- [ ] **Step 4: Commit**

```bash
git add Program.cs Commands/MiscCommands.cs
git commit -m "refactor: wire testpfx and export through System.CommandLine"
```

---

### Task 2.3: Wire `ssh` and `gpg`

**Files:**
- Modify: `Commands/MiscCommands.cs`
- Modify: `Program.cs`

- [ ] **Step 1: Add SSH subcommand**

Add to `Commands/MiscCommands.cs`:

```csharp
public static Command BuildSshCommand()
{
    var keyArg = new Argument<string>("keyName", "Name for the output key files.");
    var commentArg = new Argument<string>("comment", "Comment embedded in the public key.");
    var dirArg = new Argument<string>("exportDirectory", "Directory where keys will be written.");

    var cmd = new Command("ssh", "Generate a 4096-bit RSA SSH keypair.");
    cmd.AddArgument(keyArg);
    cmd.AddArgument(commentArg);
    cmd.AddArgument(dirArg);
    cmd.SetHandler((string keyName, string comment, string dir) =>
    {
        Common.EnsureDirectoryExists(dir);
        Cryptography.generateSshKeyPair(keyName, comment, dir);
    }, keyArg, commentArg, dirArg);
    return cmd;
}

public static Command BuildGpgCommand()
{
    var keyArg = new Argument<string>("keyName", "Name for the output key files.");
    var userArg = new Argument<string>("userName", "Real name for the GPG User ID.");
    var emailArg = new Argument<string>("email", "Email for the GPG User ID.");
    var passArg = new Argument<string>("passphrase", "Passphrase to protect the private key.");
    var dirArg = new Argument<string>("exportDirectory", "Directory where keys will be written.");

    var cmd = new Command("gpg", "Generate a 4096-bit RSA GPG keypair for commit signing.");
    cmd.AddArgument(keyArg);
    cmd.AddArgument(userArg);
    cmd.AddArgument(emailArg);
    cmd.AddArgument(passArg);
    cmd.AddArgument(dirArg);
    cmd.SetHandler((string keyName, string user, string email, string pass, string dir) =>
    {
        Common.EnsureDirectoryExists(dir);
        Cryptography.generateGpgKeyPair(keyName, user, email, pass, dir);
    }, keyArg, userArg, emailArg, passArg, dirArg);
    return cmd;
}
```

- [ ] **Step 2: Register in Program.cs**

```csharp
root.AddCommand(MiscCommands.BuildSshCommand());
root.AddCommand(MiscCommands.BuildGpgCommand());
```

- [ ] **Step 3: Smoke test**

```bash
dotnet run --project Certifactory.csproj -- ssh --help
dotnet run --project Certifactory.csproj -- gpg --help
```

Expected: both help screens print the 3 / 5 expected positional args.

- [ ] **Step 4: Commit**

```bash
git add Program.cs Commands/MiscCommands.cs
git commit -m "refactor: wire ssh and gpg through System.CommandLine"
```

---

### Task 2.4: Wire `ca`, `server`, `smime` through System.CommandLine (still RSA-only)

**Files:**
- Create: `Commands/CaCommand.cs`
- Create: `Commands/ServerCommand.cs`
- Create: `Commands/SmimeCommand.cs`
- Modify: `Program.cs`

These commands continue to call into the existing `Cryptography.buildXxx` methods unchanged. The `--algorithm` option will be added in Phase 4; for now just preserve behavior.

- [ ] **Step 1: Create `Commands/CaCommand.cs`**

```csharp
namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

public static class CaCommand
{
    public static Command Build()
    {
        var nameArg = new Argument<string>("certificateName", "CN for the root CA.");
        var passArg = new Argument<string>("certificatePassword", "Password to secure the PFX.");
        var dirArg = new Argument<string>("exportDirectory", "Directory where the PFX will be written.");

        var cmd = new Command("ca", "Generate a self-signed root CA certificate.");
        cmd.AddArgument(nameArg);
        cmd.AddArgument(passArg);
        cmd.AddArgument(dirArg);
        cmd.SetHandler((string name, string pwd, string dir) =>
        {
            Common.EnsureDirectoryExists(dir);
            X509Certificate2 cert = Cryptography.buildRootCACertificate(name, pwd);
            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            byte[] data = cert.Export(X509ContentType.Pfx, pwd);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, data);
            Console.WriteLine("Certificate exported to " + path);
        }, nameArg, passArg, dirArg);
        return cmd;
    }
}
```

- [ ] **Step 2: Create `Commands/ServerCommand.cs`**

```csharp
namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

public static class ServerCommand
{
    public static Command Build()
    {
        var nameArg = new Argument<string>("certificateName", "CN / DNS name for the server.");
        var passArg = new Argument<string>("certificatePassword", "Password to secure the PFX.");
        var ipArg = new Argument<string>("serverIP", "IP address of the target server (or empty string).");
        var caArg = new Argument<string>("rootCA", "Absolute path to the root CA PFX.");
        var caPassArg = new Argument<string>("rootCAPassword", "Password for the root CA PFX.");
        var dirArg = new Argument<string>("exportDirectory", "Directory where the PFX will be written.");

        var cmd = new Command("server", "Generate a server certificate signed by a root CA.");
        cmd.AddArgument(nameArg);
        cmd.AddArgument(passArg);
        cmd.AddArgument(ipArg);
        cmd.AddArgument(caArg);
        cmd.AddArgument(caPassArg);
        cmd.AddArgument(dirArg);
        cmd.SetHandler((string name, string pwd, string ip, string ca, string caPwd, string dir) =>
        {
            Common.EnsureDirectoryExists(dir);
            X509Certificate2 cert = Cryptography.buildSelfSignedServerCertificate(name, pwd, ip, ca, caPwd);
            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            byte[] data = cert.Export(X509ContentType.Pfx, pwd);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, data);
            Console.WriteLine("Certificate exported to " + path);
        }, nameArg, passArg, ipArg, caArg, caPassArg, dirArg);
        return cmd;
    }
}
```

- [ ] **Step 3: Create `Commands/SmimeCommand.cs`**

```csharp
namespace Soverance.Certifactory.Commands;

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

public static class SmimeCommand
{
    public static Command Build()
    {
        var nameArg = new Argument<string>("certificateName", "CN for the S/MIME certificate.");
        var passArg = new Argument<string>("certificatePassword", "Password to secure the PFX.");
        var emailArg = new Argument<string>("userEmail", "Email address embedded in the SAN.");
        var caArg = new Argument<string>("rootCA", "Absolute path to the root CA PFX.");
        var caPassArg = new Argument<string>("rootCAPassword", "Password for the root CA PFX.");
        var dirArg = new Argument<string>("exportDirectory", "Directory where the PFX will be written.");

        var cmd = new Command("smime", "Generate an S/MIME certificate signed by a root CA.");
        cmd.AddArgument(nameArg);
        cmd.AddArgument(passArg);
        cmd.AddArgument(emailArg);
        cmd.AddArgument(caArg);
        cmd.AddArgument(caPassArg);
        cmd.AddArgument(dirArg);
        cmd.SetHandler((string name, string pwd, string email, string ca, string caPwd, string dir) =>
        {
            Common.EnsureDirectoryExists(dir);
            X509Certificate2 cert = Cryptography.buildSelfSignedSmimeCertificate(name, pwd, email, ca, caPwd);
            Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
            byte[] data = cert.Export(X509ContentType.Pfx, pwd);
            string path = Path.Combine(dir, name + ".pfx");
            File.WriteAllBytes(path, data);
            Console.WriteLine("Certificate exported to " + path);
        }, nameArg, passArg, emailArg, caArg, caPassArg, dirArg);
        return cmd;
    }
}
```

- [ ] **Step 4: Register in Program.cs**

Update `Program.cs`:

```csharp
namespace Soverance.Certifactory;

using System.CommandLine;
using Soverance.Certifactory.Commands;

class Program
{
    static int Main(string[] args)
    {
        var root = new RootCommand("Soverance Studios - Certifactory certificate generation utility.");
        root.AddCommand(CaCommand.Build());
        root.AddCommand(ServerCommand.Build());
        root.AddCommand(SmimeCommand.Build());
        root.AddCommand(MiscCommands.BuildTestPfxCommand());
        root.AddCommand(MiscCommands.BuildExportCommand());
        root.AddCommand(MiscCommands.BuildSshCommand());
        root.AddCommand(MiscCommands.BuildGpgCommand());
        root.AddCommand(MiscCommands.BuildVersionCommand());
        return root.Invoke(args);
    }
}
```

- [ ] **Step 5: End-to-end smoke test**

Generate a CA + server cert + S/MIME cert and validate the output:

```bash
mkdir -p /tmp/cert-smoke
dotnet run --project Certifactory.csproj -- ca smoke-ca SmokePass /tmp/cert-smoke
dotnet run --project Certifactory.csproj -- testpfx /tmp/cert-smoke/smoke-ca.pfx SmokePass
dotnet run --project Certifactory.csproj -- server smoke.example.com SmokePass "" /tmp/cert-smoke/smoke-ca.pfx SmokePass /tmp/cert-smoke
dotnet run --project Certifactory.csproj -- smime test@example.com SmokePass test@example.com /tmp/cert-smoke/smoke-ca.pfx SmokePass /tmp/cert-smoke
```

Expected: all four commands print thumbprints and export PFX files. `testpfx` shows correct subject/issuer.

- [ ] **Step 6: Commit**

```bash
git add Program.cs Commands/
git commit -m "refactor: wire ca/server/smime through System.CommandLine"
```

---

## Phase 3 — Introduce IPqSigner abstraction (RSA only)

This phase introduces the abstraction without adding new algorithms. The aim is to land the architectural seam now so Phase 4–6 are mechanical.

### Task 3.1: Define IPqSigner interface

**Files:**
- Create: `Pq/IPqSigner.cs`

- [ ] **Step 1: Define the interface**

Create `Pq/IPqSigner.cs`:

```csharp
namespace Soverance.Certifactory.Pq;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;

/// <summary>
/// Algorithm-agnostic signing primitive used by CertificateBuilder.
/// One instance carries one keypair; create a fresh instance per cert.
/// </summary>
public interface IPqSigner
{
    /// <summary>Stable identifier used by SignerFactory and CLI (e.g. "rsa-4096", "ml-dsa-65").</summary>
    string AlgorithmId { get; }

    /// <summary>The keypair produced by <see cref="GenerateKeyPair"/> (or loaded from an existing key).</summary>
    AsymmetricCipherKeyPair KeyPair { get; }

    /// <summary>Generate and store a fresh keypair on this signer instance.</summary>
    void GenerateKeyPair();

    /// <summary>Load an existing keypair (used when issuing leaf certs from a CA's private key).</summary>
    void LoadKeyPair(AsymmetricCipherKeyPair keyPair);

    /// <summary>BC signature factory used by X509V3CertificateGenerator.</summary>
    ISignatureFactory CreateSignatureFactory();
}
```

- [ ] **Step 2: Build to verify the file compiles**

```bash
dotnet build Certifactory.sln
```

- [ ] **Step 3: Commit**

```bash
git add Pq/IPqSigner.cs
git commit -m "feat: add IPqSigner abstraction for algorithm-pluggable signing"
```

---

### Task 3.2: Implement RsaSigner

**Files:**
- Create: `Pq/Signing.cs`
- Create: `Certifactory.Tests/SigningTests.cs`

- [ ] **Step 1: Write the failing test**

Create `Certifactory.Tests/SigningTests.cs`:

```csharp
using FluentAssertions;
using Org.BouncyCastle.Crypto.Operators;
using Soverance.Certifactory.Pq;
using Xunit;

namespace Certifactory.Tests;

public class SigningTests
{
    [Fact]
    public void RsaSigner_generates_4096_bit_key()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        signer.AlgorithmId.Should().Be("rsa-4096");
        signer.KeyPair.Should().NotBeNull();
        signer.KeyPair.Public.Should().NotBeNull();
        signer.KeyPair.Private.Should().NotBeNull();
    }

    [Fact]
    public void RsaSigner_creates_signature_factory()
    {
        var signer = new RsaSigner();
        signer.GenerateKeyPair();
        signer.CreateSignatureFactory().Should().NotBeNull();
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

Expected: compile error, `RsaSigner` does not exist.

- [ ] **Step 3: Implement RsaSigner**

Create `Pq/Signing.cs`:

```csharp
namespace Soverance.Certifactory.Pq;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

public sealed class RsaSigner : IPqSigner
{
    public string AlgorithmId => "rsa-4096";
    public AsymmetricCipherKeyPair KeyPair { get; private set; } = null!;

    public void GenerateKeyPair()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new RsaKeyGenerationParameters(
            BigInteger.ValueOf(0x10001), new SecureRandom(), 4096, 12));
        KeyPair = gen.GenerateKeyPair();
    }

    public void LoadKeyPair(AsymmetricCipherKeyPair keyPair) => KeyPair = keyPair;

    public ISignatureFactory CreateSignatureFactory()
        => new Asn1SignatureFactory("SHA256WITHRSA", KeyPair.Private, new SecureRandom());
}
```

- [ ] **Step 4: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

Expected: 2 passing.

- [ ] **Step 5: Commit**

```bash
git add Pq/Signing.cs Certifactory.Tests/SigningTests.cs
git commit -m "feat: RsaSigner implementation of IPqSigner"
```

---

### Task 3.3: Add SignerFactory

**Files:**
- Modify: `Pq/Signing.cs`
- Modify: `Certifactory.Tests/SigningTests.cs`

- [ ] **Step 1: Write the failing test**

Append to `SigningTests.cs`:

```csharp
[Fact]
public void SignerFactory_creates_rsa_signer()
{
    IPqSigner s = SignerFactory.Create("rsa-4096");
    s.Should().BeOfType<RsaSigner>();
}

[Fact]
public void SignerFactory_throws_on_unknown_algorithm()
{
    Action act = () => SignerFactory.Create("bogus-algo");
    act.Should().Throw<ArgumentException>().WithMessage("*bogus-algo*");
}
```

- [ ] **Step 2: Run to verify failure**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

Expected: compile error.

- [ ] **Step 3: Implement SignerFactory**

Append to `Pq/Signing.cs`:

```csharp
public static class SignerFactory
{
    public const string Rsa4096 = "rsa-4096";

    public static IPqSigner Create(string algorithmId)
    {
        return algorithmId switch
        {
            Rsa4096 => new RsaSigner(),
            _ => throw new ArgumentException(
                $"Unknown signing algorithm: {algorithmId}", nameof(algorithmId))
        };
    }

    public static IReadOnlyList<string> SupportedAlgorithms => new[] { Rsa4096 };
}
```

- [ ] **Step 4: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

Expected: 4 passing.

- [ ] **Step 5: Commit**

```bash
git add Pq/Signing.cs Certifactory.Tests/SigningTests.cs
git commit -m "feat: SignerFactory dispatches by algorithm string"
```

---

### Task 3.4: Build CertificateBuilder for root CA via IPqSigner

**Files:**
- Create: `Pq/CertificateBuilder.cs`
- Create: `Pq/PfxExporter.cs`
- Create: `Certifactory.Tests/CertificateBuilderTests.cs`

- [ ] **Step 1: Write the failing test**

Create `Certifactory.Tests/CertificateBuilderTests.cs`:

```csharp
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Soverance.Certifactory.Pq;
using Xunit;

namespace Certifactory.Tests;

public class CertificateBuilderTests
{
    [Fact]
    public void Builds_RSA_root_CA_with_self_signed_subject_and_basic_constraints()
    {
        var signer = SignerFactory.Create("rsa-4096");
        signer.GenerateKeyPair();

        var spec = new CertificateSpec(
            Purpose: CertificatePurpose.RootCa,
            CommonName: "test-root-ca",
            Password: "TestPass",
            Signer: signer,
            ServerIp: null,
            EmailAddress: null,
            Issuer: null);

        X509Certificate2 cert = CertificateBuilder.BuildCertificate(spec);

        cert.Subject.Should().Be("CN=test-root-ca");
        cert.Issuer.Should().Be("CN=test-root-ca");
        // basic constraints: cA=TRUE
        var bc = cert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Single();
        bc.CertificateAuthority.Should().BeTrue();
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
dotnet test --filter "FullyQualifiedName~CertificateBuilderTests"
```

Expected: compile error.

- [ ] **Step 3: Implement PfxExporter**

Create `Pq/PfxExporter.cs`:

```csharp
namespace Soverance.Certifactory.Pq;

using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

public static class PfxExporter
{
    /// <summary>
    /// Bundles a BC X509 cert + private key into a PFX byte array, then loads
    /// it as a .NET X509Certificate2 (the type the rest of the app uses).
    /// </summary>
    public static X509Certificate2 ToX509Certificate2(
        X509Certificate bcCert,
        AsymmetricKeyParameter privateKey,
        string friendlyName,
        string password)
    {
        var store = new Pkcs12StoreBuilder().Build();
        var certEntry = new X509CertificateEntry(bcCert);
        store.SetCertificateEntry(friendlyName, certEntry);
        store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey),
            new[] { certEntry });

        using var ms = new MemoryStream();
        store.Save(ms, password.ToCharArray(), new SecureRandom());
        return new X509Certificate2(ms.ToArray(), password,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }
}
```

- [ ] **Step 4: Implement CertificateBuilder**

Create `Pq/CertificateBuilder.cs`:

```csharp
namespace Soverance.Certifactory.Pq;

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

public enum CertificatePurpose { RootCa, Server, Smime }

public sealed record CertificateSpec(
    CertificatePurpose Purpose,
    string CommonName,
    string Password,
    IPqSigner Signer,
    string? ServerIp,
    string? EmailAddress,
    IssuerInfo? Issuer);

public sealed record IssuerInfo(
    X509Certificate2 Certificate,
    IPqSigner Signer);

public static class CertificateBuilder
{
    public static X509Certificate2 BuildCertificate(CertificateSpec spec)
    {
        if (spec.Signer.KeyPair is null)
            spec.Signer.GenerateKeyPair();

        var random = new SecureRandom();
        var gen = new X509V3CertificateGenerator();
        var subject = BuildSubject(spec);
        gen.SetSerialNumber(new BigInteger(159, random).Abs().Add(BigInteger.One));
        gen.SetSubjectDN(subject);
        gen.SetIssuerDN(spec.Issuer is null ? subject : ParseDn(spec.Issuer.Certificate.SubjectName.Name));
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(GetValidityDays(spec.Purpose)));
        gen.SetPublicKey(spec.Signer.KeyPair.Public);

        AddCommonExtensions(gen, spec);

        ISignatureFactory sigFactory = spec.Issuer is null
            ? spec.Signer.CreateSignatureFactory()
            : spec.Issuer.Signer.CreateSignatureFactory();

        Org.BouncyCastle.X509.X509Certificate bcCert = gen.Generate(sigFactory);

        return PfxExporter.ToX509Certificate2(
            bcCert, spec.Signer.KeyPair.Private, spec.CommonName, spec.Password);
    }

    private static X509Name BuildSubject(CertificateSpec spec) => spec.Purpose switch
    {
        CertificatePurpose.RootCa => new X509Name($"CN={spec.CommonName}"),
        CertificatePurpose.Server => new X509Name($"CN={spec.CommonName}"),
        CertificatePurpose.Smime  => new X509Name(
            $"CN={spec.CommonName},C=US,ST=Georgia,L=Atlanta,O=Soverance Studios,OU=Information"),
        _ => throw new ArgumentOutOfRangeException()
    };

    private static X509Name ParseDn(string dn) => new X509Name(dn);

    private static int GetValidityDays(CertificatePurpose purpose) => purpose switch
    {
        CertificatePurpose.RootCa => 7300,  // 20 years
        CertificatePurpose.Server => 396,   // iOS limit
        CertificatePurpose.Smime  => 3650,  // 10 years
        _ => 365
    };

    private static void AddCommonExtensions(
        X509V3CertificateGenerator gen, CertificateSpec spec)
    {
        switch (spec.Purpose)
        {
            case CertificatePurpose.RootCa:
                gen.AddExtension(X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: true));
                gen.AddExtension(X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(spec.Signer.KeyPair.Public));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(
                        KeyPurposeID.id_kp_serverAuth,
                        KeyPurposeID.id_kp_clientAuth,
                        KeyPurposeID.id_kp_codeSigning,
                        KeyPurposeID.id_kp_emailProtection,
                        new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12")));
                break;

            case CertificatePurpose.Server:
                gen.AddExtension(X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: false));
                gen.AddExtension(X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.DigitalSignature
                        | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth, KeyPurposeID.id_kp_clientAuth));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(spec.Signer.KeyPair.Public));
                if (spec.Issuer is not null)
                {
                    gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                        new AuthorityKeyIdentifierStructure(
                            DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate)));
                }
                AddServerSan(gen, spec);
                break;

            case CertificatePurpose.Smime:
                gen.AddExtension(X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: false));
                gen.AddExtension(X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.NonRepudiation | KeyUsage.DigitalSignature
                        | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment));
                gen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(
                        KeyPurposeID.id_kp_emailProtection,
                        new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12")));
                gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(spec.Signer.KeyPair.Public));
                if (spec.Issuer is not null)
                {
                    gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                        new AuthorityKeyIdentifierStructure(
                            DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate)));
                }
                AddSmimeSan(gen, spec);
                break;
        }
    }

    private static void AddServerSan(X509V3CertificateGenerator gen, CertificateSpec spec)
    {
        var names = new List<GeneralName>
        {
            new GeneralName(GeneralName.DnsName, spec.CommonName)
        };
        if (!string.IsNullOrEmpty(spec.ServerIp))
        {
            names.Add(new GeneralName(GeneralName.IPAddress, spec.ServerIp));
        }
        gen.AddExtension(X509Extensions.SubjectAlternativeName, false,
            new GeneralNames(names.ToArray()));
    }

    private static void AddSmimeSan(X509V3CertificateGenerator gen, CertificateSpec spec)
    {
        if (string.IsNullOrEmpty(spec.EmailAddress))
            throw new ArgumentException("S/MIME spec requires EmailAddress");
        var names = new[]
        {
            new GeneralName(GeneralName.Rfc822Name, spec.EmailAddress)
        };
        gen.AddExtension(X509Extensions.SubjectAlternativeName, false,
            new GeneralNames(names));
    }
}
```

- [ ] **Step 5: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~CertificateBuilderTests"
```

Expected: 1 passing.

- [ ] **Step 6: Commit**

```bash
git add Pq/CertificateBuilder.cs Pq/PfxExporter.cs Certifactory.Tests/CertificateBuilderTests.cs
git commit -m "feat: CertificateBuilder for root CA via IPqSigner abstraction"
```

---

### Task 3.5: Add server-cert chain test

**Files:**
- Modify: `Certifactory.Tests/CertificateBuilderTests.cs`

- [ ] **Step 1: Write the failing test**

Append to `CertificateBuilderTests.cs`:

```csharp
[Fact]
public void Server_cert_signed_by_CA_chains_correctly()
{
    var caSigner = SignerFactory.Create("rsa-4096");
    caSigner.GenerateKeyPair();
    var caSpec = new CertificateSpec(
        CertificatePurpose.RootCa, "chain-test-ca", "Pass", caSigner,
        ServerIp: null, EmailAddress: null, Issuer: null);
    var caCert = CertificateBuilder.BuildCertificate(caSpec);

    var leafSigner = SignerFactory.Create("rsa-4096");
    leafSigner.GenerateKeyPair();
    var leafSpec = new CertificateSpec(
        CertificatePurpose.Server, "chain-test.example.com", "Pass", leafSigner,
        ServerIp: "10.0.0.1",
        EmailAddress: null,
        Issuer: new IssuerInfo(caCert, caSigner));
    var leaf = CertificateBuilder.BuildCertificate(leafSpec);

    leaf.Issuer.Should().Be("CN=chain-test-ca");
    leaf.Subject.Should().Be("CN=chain-test.example.com");

    leaf.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Should().ContainSingle();
    leaf.Extensions.Should().Contain(e => e.Oid?.Value == "2.5.29.35"); // AuthorityKeyIdentifier
    leaf.Extensions.OfType<X509BasicConstraintsExtension>().Single()
        .CertificateAuthority.Should().BeFalse();
}
```

- [ ] **Step 2: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~CertificateBuilderTests"
```

Expected: 2 passing. If issuer DN parsing has trouble, the test will surface it.

- [ ] **Step 3: Commit**

```bash
git add Certifactory.Tests/CertificateBuilderTests.cs
git commit -m "test: server cert chains correctly to root CA"
```

---

### Task 3.6: Add S/MIME test

**Files:**
- Modify: `Certifactory.Tests/CertificateBuilderTests.cs`

- [ ] **Step 1: Write the failing test**

Append:

```csharp
[Fact]
public void Smime_cert_includes_email_in_san_and_correct_eku()
{
    var caSigner = SignerFactory.Create("rsa-4096");
    caSigner.GenerateKeyPair();
    var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "smime-test-ca", "Pass", caSigner,
        ServerIp: null, EmailAddress: null, Issuer: null));

    var leafSigner = SignerFactory.Create("rsa-4096");
    leafSigner.GenerateKeyPair();
    var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.Smime, "alice@example.com", "Pass", leafSigner,
        ServerIp: null,
        EmailAddress: "alice@example.com",
        Issuer: new IssuerInfo(caCert, caSigner)));

    var ekus = leaf.Extensions
        .OfType<X509EnhancedKeyUsageExtension>()
        .Single().EnhancedKeyUsages;
    ekus.Cast<System.Security.Cryptography.Oid>()
        .Should().Contain(o => o.Value == "1.3.6.1.5.5.7.3.4"); // emailProtection

    var sanExt = leaf.Extensions.Single(e => e.Oid?.Value == "2.5.29.17");
    sanExt.Format(false).Should().Contain("alice@example.com");
}
```

- [ ] **Step 2: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~CertificateBuilderTests"
```

Expected: 3 passing.

- [ ] **Step 3: Commit**

```bash
git add Certifactory.Tests/CertificateBuilderTests.cs
git commit -m "test: smime cert has email SAN and emailProtection EKU"
```

---

### Task 3.7: Wire CertificateBuilder into the three commands

**Files:**
- Modify: `Commands/CaCommand.cs`
- Modify: `Commands/ServerCommand.cs`
- Modify: `Commands/SmimeCommand.cs`

The handlers are currently calling `Cryptography.buildXxx`. Replace each with calls into `CertificateBuilder.BuildCertificate`. Behavior is unchanged from the user's perspective; this is the actual cutover.

- [ ] **Step 1: Update CaCommand handler**

Replace the `cmd.SetHandler` body in `Commands/CaCommand.cs` with:

```csharp
cmd.SetHandler((string name, string pwd, string dir) =>
{
    Common.EnsureDirectoryExists(dir);
    var signer = Pq.SignerFactory.Create(Pq.SignerFactory.Rsa4096);
    var cert = Pq.CertificateBuilder.BuildCertificate(new Pq.CertificateSpec(
        Pq.CertificatePurpose.RootCa, name, pwd, signer,
        ServerIp: null, EmailAddress: null, Issuer: null));
    Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
    byte[] data = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, pwd);
    string path = Path.Combine(dir, name + ".pfx");
    File.WriteAllBytes(path, data);
    Console.WriteLine("Certificate exported to " + path);
}, nameArg, passArg, dirArg);
```

- [ ] **Step 2: Update ServerCommand and SmimeCommand handlers similarly**

`ServerCommand`:

```csharp
cmd.SetHandler((string name, string pwd, string ip, string ca, string caPwd, string dir) =>
{
    Common.EnsureDirectoryExists(dir);
    var caCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
        ca, caPwd, System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet
        | System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
    var caSigner = Pq.SignerFactory.Create(Pq.SignerFactory.Rsa4096);
    caSigner.LoadKeyPair(Pq.PfxExporter.ExtractKeyPair(caCert));

    var leafSigner = Pq.SignerFactory.Create(Pq.SignerFactory.Rsa4096);
    var cert = Pq.CertificateBuilder.BuildCertificate(new Pq.CertificateSpec(
        Pq.CertificatePurpose.Server, name, pwd, leafSigner,
        ServerIp: ip,
        EmailAddress: null,
        Issuer: new Pq.IssuerInfo(caCert, caSigner)));
    Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
    byte[] data = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, pwd);
    string path = Path.Combine(dir, name + ".pfx");
    File.WriteAllBytes(path, data);
    Console.WriteLine("Certificate exported to " + path);
}, nameArg, passArg, ipArg, caArg, caPassArg, dirArg);
```

`SmimeCommand` is identical except `Purpose: CertificatePurpose.Smime` and `EmailAddress: email`, `ServerIp: null`.

- [ ] **Step 3: Add ExtractKeyPair to PfxExporter**

The handlers need to pull the CA's keypair out of the loaded PFX. Add to `Pq/PfxExporter.cs`:

```csharp
public static AsymmetricCipherKeyPair ExtractKeyPair(X509Certificate2 cert)
{
    using var rsa = cert.GetRSAPrivateKey()
        ?? throw new InvalidOperationException("CA certificate has no RSA private key.");
    var bcKey = DotNetUtilities.GetRsaKeyPair(rsa);
    return bcKey;
}
```

(Add `using Org.BouncyCastle.Security;` and `using System.Security.Cryptography.X509Certificates;` to the file.)

- [ ] **Step 4: Remove the old Cryptography methods**

Delete `buildRootCACertificate`, `buildSelfSignedServerCertificate`, `buildSelfSignedSmimeCertificate` from `Cryptography.cs`. Keep all other methods.

- [ ] **Step 5: Run all tests + smoke test**

```bash
dotnet test
mkdir -p /tmp/cert-smoke2
dotnet run --project Certifactory.csproj -- ca smoke-ca SmokePass /tmp/cert-smoke2
dotnet run --project Certifactory.csproj -- server smoke.example.com SmokePass "" /tmp/cert-smoke2/smoke-ca.pfx SmokePass /tmp/cert-smoke2
dotnet run --project Certifactory.csproj -- smime alice@example.com SmokePass alice@example.com /tmp/cert-smoke2/smoke-ca.pfx SmokePass /tmp/cert-smoke2
dotnet run --project Certifactory.csproj -- testpfx /tmp/cert-smoke2/smoke.example.com.pfx SmokePass
```

Expected: all green; testpfx shows Issuer = `CN=smoke-ca`, server cert has the AuthorityKeyIdentifier extension that the old code was missing.

- [ ] **Step 6: Commit**

```bash
git add Commands/ Cryptography.cs Pq/PfxExporter.cs
git commit -m "refactor: route ca/server/smime through CertificateBuilder + IPqSigner"
```

---

## Phase 4 — Add ML-DSA support

### Task 4.1: Implement MlDsaSigner

**Files:**
- Modify: `Pq/Signing.cs`
- Modify: `Certifactory.Tests/SigningTests.cs`

> **Important:** Use the namespace path verified by Task 0.2's spike. The code below assumes `Org.BouncyCastle.Pqc.Crypto.MLDsa`. If the spike found a different path (e.g. `MlDsa` casing), update accordingly.

- [ ] **Step 1: Write the failing test**

Append to `SigningTests.cs`:

```csharp
[Fact]
public void MlDsaSigner_generates_keypair_and_signature_factory()
{
    var signer = new MlDsaSigner();
    signer.GenerateKeyPair();
    signer.AlgorithmId.Should().Be("ml-dsa-65");
    signer.KeyPair.Should().NotBeNull();
    signer.CreateSignatureFactory().Should().NotBeNull();
}

[Fact]
public void SignerFactory_creates_ml_dsa_signer()
{
    SignerFactory.Create("ml-dsa-65").Should().BeOfType<MlDsaSigner>();
}
```

- [ ] **Step 2: Run to verify failure**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

- [ ] **Step 3: Implement MlDsaSigner**

Append to `Pq/Signing.cs`:

```csharp
using Org.BouncyCastle.Pqc.Crypto.MLDsa;

public sealed class MlDsaSigner : IPqSigner
{
    public string AlgorithmId => "ml-dsa-65";
    public AsymmetricCipherKeyPair KeyPair { get; private set; } = null!;

    public void GenerateKeyPair()
    {
        var random = new SecureRandom();
        var gen = new MLDsaKeyPairGenerator();
        gen.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
        KeyPair = gen.GenerateKeyPair();
    }

    public void LoadKeyPair(AsymmetricCipherKeyPair keyPair) => KeyPair = keyPair;

    public ISignatureFactory CreateSignatureFactory()
    {
        // BC's Asn1SignatureFactory accepts the algorithm name; for ML-DSA-65
        // it should be "ML-DSA-65". If the spike found a different string,
        // use that instead.
        return new Asn1SignatureFactory("ML-DSA-65", KeyPair.Private, new SecureRandom());
    }
}
```

- [ ] **Step 4: Update SignerFactory to register ML-DSA**

Modify the `SignerFactory` class:

```csharp
public static class SignerFactory
{
    public const string Rsa4096 = "rsa-4096";
    public const string MlDsa65 = "ml-dsa-65";

    public static IPqSigner Create(string algorithmId)
    {
        return algorithmId switch
        {
            Rsa4096 => new RsaSigner(),
            MlDsa65 => new MlDsaSigner(),
            _ => throw new ArgumentException(
                $"Unknown signing algorithm: {algorithmId}", nameof(algorithmId))
        };
    }

    public static IReadOnlyList<string> SupportedAlgorithms => new[] { Rsa4096, MlDsa65 };
}
```

- [ ] **Step 5: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

Expected: 6 passing. If `Asn1SignatureFactory` rejects the `"ML-DSA-65"` algorithm string, fall back to manually building a `MLDsaSigner` from BC's PQC namespace and adapting it to `ISignatureFactory` (BC has `MLDsaSigner` class with `Init(true, key)` / `Update(buf)` / `GenerateSignature()` methods — wrap in a tiny `IStreamCalculator` adapter).

- [ ] **Step 6: Commit**

```bash
git add Pq/Signing.cs Certifactory.Tests/SigningTests.cs
git commit -m "feat: MlDsaSigner using BouncyCastle ML-DSA-65"
```

---

### Task 4.2: ML-DSA root CA end-to-end test

**Files:**
- Modify: `Certifactory.Tests/CertificateBuilderTests.cs`

- [ ] **Step 1: Write the failing test**

Append:

```csharp
[Fact]
public void ML_DSA_root_CA_can_be_built_and_loaded()
{
    var signer = SignerFactory.Create("ml-dsa-65");
    var spec = new CertificateSpec(
        CertificatePurpose.RootCa, "ml-dsa-test-ca", "Pass", signer,
        ServerIp: null, EmailAddress: null, Issuer: null);
    var cert = CertificateBuilder.BuildCertificate(spec);

    cert.Subject.Should().Be("CN=ml-dsa-test-ca");
    cert.SignatureAlgorithm.Value.Should().NotBe("1.2.840.113549.1.1.11"); // not RSA-SHA256
    // ML-DSA-65 OID per FIPS 204: 2.16.840.1.101.3.4.3.18
    cert.SignatureAlgorithm.Value.Should().Be("2.16.840.1.101.3.4.3.18");
}
```

- [ ] **Step 2: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~CertificateBuilderTests"
```

If this fails because BC's `Asn1SignatureFactory` does not yet emit ML-DSA OIDs in TBS, you'll see a different signature algorithm in the cert. In that case, update the SignerFactory's `MlDsaSigner.CreateSignatureFactory()` to manually construct an `AlgorithmIdentifier` with OID `2.16.840.1.101.3.4.3.18` and a `IStreamCalculator` that drives BC's `MLDsaSigner` directly. This is a known integration friction point; expect to spend up to an hour here.

- [ ] **Step 3: Commit**

```bash
git add Certifactory.Tests/CertificateBuilderTests.cs
git commit -m "test: ML-DSA root CA produces correct signature algorithm OID"
```

---

### Task 4.3: ML-DSA server + S/MIME chain tests

**Files:**
- Modify: `Certifactory.Tests/CertificateBuilderTests.cs`

- [ ] **Step 1: Write the failing tests**

Append:

```csharp
[Fact]
public void ML_DSA_server_cert_signed_by_ML_DSA_CA_chains()
{
    var caSigner = SignerFactory.Create("ml-dsa-65");
    var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "ml-dsa-chain-ca", "Pass", caSigner,
        null, null, null));

    var leafSigner = SignerFactory.Create("ml-dsa-65");
    var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.Server, "ml-dsa.example.com", "Pass", leafSigner,
        "10.0.0.2", null, new IssuerInfo(caCert, caSigner)));

    leaf.Issuer.Should().Be("CN=ml-dsa-chain-ca");
}

[Fact]
public void ML_DSA_smime_cert_signed_by_ML_DSA_CA_chains()
{
    var caSigner = SignerFactory.Create("ml-dsa-65");
    var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "ml-dsa-smime-ca", "Pass", caSigner,
        null, null, null));

    var leafSigner = SignerFactory.Create("ml-dsa-65");
    var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.Smime, "bob@example.com", "Pass", leafSigner,
        null, "bob@example.com", new IssuerInfo(caCert, caSigner)));

    leaf.Issuer.Should().Be("CN=ml-dsa-smime-ca");
}
```

- [ ] **Step 2: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~CertificateBuilderTests"
```

- [ ] **Step 3: Commit**

```bash
git add Certifactory.Tests/CertificateBuilderTests.cs
git commit -m "test: ML-DSA server and smime certs chain to ML-DSA CA"
```

---

### Task 4.4: Add `--algorithm` flag to ca/server/smime commands

**Files:**
- Modify: `Commands/CaCommand.cs`
- Modify: `Commands/ServerCommand.cs`
- Modify: `Commands/SmimeCommand.cs`

- [ ] **Step 1: Add `--algorithm` option to CaCommand**

In `Commands/CaCommand.cs`, add the option and update the handler:

```csharp
var algoOpt = new Option<string>(
    name: "--algorithm",
    description: "Signing algorithm: rsa-4096 (default), ml-dsa-65, slh-dsa-256s, hybrid",
    getDefaultValue: () => Pq.SignerFactory.Rsa4096);
algoOpt.AddCompletions(Pq.SignerFactory.SupportedAlgorithms.ToArray());

var cmd = new Command("ca", "Generate a self-signed root CA certificate.");
cmd.AddArgument(nameArg);
cmd.AddArgument(passArg);
cmd.AddArgument(dirArg);
cmd.AddOption(algoOpt);
cmd.SetHandler((string name, string pwd, string dir, string algo) =>
{
    Common.EnsureDirectoryExists(dir);
    var signer = Pq.SignerFactory.Create(algo);
    var cert = Pq.CertificateBuilder.BuildCertificate(new Pq.CertificateSpec(
        Pq.CertificatePurpose.RootCa, name, pwd, signer,
        ServerIp: null, EmailAddress: null, Issuer: null));
    Console.WriteLine($"Algorithm = {algo}");
    Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
    byte[] data = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, pwd);
    string path = Path.Combine(dir, name + ".pfx");
    File.WriteAllBytes(path, data);
    Console.WriteLine("Certificate exported to " + path);
}, nameArg, passArg, dirArg, algoOpt);
return cmd;
```

- [ ] **Step 2: Add `--algorithm` option to ServerCommand**

Replace the body of `Commands/ServerCommand.cs`'s `Build` method with:

```csharp
public static Command Build()
{
    var nameArg = new Argument<string>("certificateName", "CN / DNS name for the server.");
    var passArg = new Argument<string>("certificatePassword", "Password to secure the PFX.");
    var ipArg = new Argument<string>("serverIP", "IP address of the target server (or empty string).");
    var caArg = new Argument<string>("rootCA", "Absolute path to the root CA PFX.");
    var caPassArg = new Argument<string>("rootCAPassword", "Password for the root CA PFX.");
    var dirArg = new Argument<string>("exportDirectory", "Directory where the PFX will be written.");

    var algoOpt = new Option<string>(
        name: "--algorithm",
        description: "Signing algorithm: rsa-4096 (default), ml-dsa-65, slh-dsa-256s, hybrid",
        getDefaultValue: () => Pq.SignerFactory.Rsa4096);
    algoOpt.AddCompletions(Pq.SignerFactory.SupportedAlgorithms.ToArray());

    var cmd = new Command("server", "Generate a server certificate signed by a root CA.");
    cmd.AddArgument(nameArg);
    cmd.AddArgument(passArg);
    cmd.AddArgument(ipArg);
    cmd.AddArgument(caArg);
    cmd.AddArgument(caPassArg);
    cmd.AddArgument(dirArg);
    cmd.AddOption(algoOpt);

    cmd.SetHandler((string name, string pwd, string ip, string ca, string caPwd, string dir, string algo) =>
    {
        Common.EnsureDirectoryExists(dir);

        var caCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
            ca, caPwd,
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet
            | System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        var caSigner = Pq.SignerFactory.CreateForCertificate(caCert);
        caSigner.LoadKeyPair(Pq.PfxExporter.ExtractKeyPair(caCert));

        var leafSigner = Pq.SignerFactory.Create(algo);
        var cert = Pq.CertificateBuilder.BuildCertificate(new Pq.CertificateSpec(
            Pq.CertificatePurpose.Server, name, pwd, leafSigner,
            ServerIp: ip,
            EmailAddress: null,
            Issuer: new Pq.IssuerInfo(caCert, caSigner)));

        Console.WriteLine($"Algorithm = {algo}");
        Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
        byte[] data = cert.Export(
            System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, pwd);
        string path = Path.Combine(dir, name + ".pfx");
        File.WriteAllBytes(path, data);
        Console.WriteLine("Certificate exported to " + path);
    }, nameArg, passArg, ipArg, caArg, caPassArg, dirArg, algoOpt);

    return cmd;
}
```

Replace the body of `Commands/SmimeCommand.cs`'s `Build` method with the same shape — note `Purpose: Smime`, `EmailAddress: email`, `ServerIp: null`:

```csharp
public static Command Build()
{
    var nameArg = new Argument<string>("certificateName", "CN for the S/MIME certificate.");
    var passArg = new Argument<string>("certificatePassword", "Password to secure the PFX.");
    var emailArg = new Argument<string>("userEmail", "Email address embedded in the SAN.");
    var caArg = new Argument<string>("rootCA", "Absolute path to the root CA PFX.");
    var caPassArg = new Argument<string>("rootCAPassword", "Password for the root CA PFX.");
    var dirArg = new Argument<string>("exportDirectory", "Directory where the PFX will be written.");

    var algoOpt = new Option<string>(
        name: "--algorithm",
        description: "Signing algorithm: rsa-4096 (default), ml-dsa-65, slh-dsa-256s, hybrid",
        getDefaultValue: () => Pq.SignerFactory.Rsa4096);
    algoOpt.AddCompletions(Pq.SignerFactory.SupportedAlgorithms.ToArray());

    var cmd = new Command("smime", "Generate an S/MIME certificate signed by a root CA.");
    cmd.AddArgument(nameArg);
    cmd.AddArgument(passArg);
    cmd.AddArgument(emailArg);
    cmd.AddArgument(caArg);
    cmd.AddArgument(caPassArg);
    cmd.AddArgument(dirArg);
    cmd.AddOption(algoOpt);

    cmd.SetHandler((string name, string pwd, string email, string ca, string caPwd, string dir, string algo) =>
    {
        Common.EnsureDirectoryExists(dir);

        var caCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
            ca, caPwd,
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet
            | System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        var caSigner = Pq.SignerFactory.CreateForCertificate(caCert);
        caSigner.LoadKeyPair(Pq.PfxExporter.ExtractKeyPair(caCert));

        var leafSigner = Pq.SignerFactory.Create(algo);
        var cert = Pq.CertificateBuilder.BuildCertificate(new Pq.CertificateSpec(
            Pq.CertificatePurpose.Smime, name, pwd, leafSigner,
            ServerIp: null,
            EmailAddress: email,
            Issuer: new Pq.IssuerInfo(caCert, caSigner)));

        Console.WriteLine($"Algorithm = {algo}");
        Console.WriteLine("Certificate Thumbprint = " + cert.Thumbprint);
        byte[] data = cert.Export(
            System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, pwd);
        string path = Path.Combine(dir, name + ".pfx");
        File.WriteAllBytes(path, data);
        Console.WriteLine("Certificate exported to " + path);
    }, nameArg, passArg, emailArg, caArg, caPassArg, dirArg, algoOpt);

    return cmd;
}
```

- [ ] **Step 3: Detect the CA's algorithm from its signature algorithm OID**

The leaf must be signed by the same algorithm the CA was created with — otherwise the chain breaks. Add to `Pq/SignerFactory.cs`:

```csharp
public static IPqSigner CreateForCertificate(
    System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
{
    string oid = cert.SignatureAlgorithm.Value!;
    return oid switch
    {
        "1.2.840.113549.1.1.11" => new RsaSigner(),       // sha256WithRSAEncryption
        "2.16.840.1.101.3.4.3.18" => new MlDsaSigner(),   // id-ml-dsa-65
        _ => throw new NotSupportedException(
            $"Cannot determine signer for CA with signature algorithm OID {oid}.")
    };
}
```

(SLH-DSA and hybrid OIDs added in later phases.)

In `ServerCommand` and `SmimeCommand`, replace the `caSigner` construction:

```csharp
var caSigner = Pq.SignerFactory.CreateForCertificate(caCert);
caSigner.LoadKeyPair(Pq.PfxExporter.ExtractKeyPair(caCert));
```

(`ExtractKeyPair` will need a per-algorithm path — Task 4.5.)

- [ ] **Step 4: Smoke test**

```bash
mkdir -p /tmp/cert-mldsa
dotnet run --project Certifactory.csproj -- ca mldsa-ca Pass1 /tmp/cert-mldsa --algorithm ml-dsa-65
dotnet run --project Certifactory.csproj -- testpfx /tmp/cert-mldsa/mldsa-ca.pfx Pass1
```

Expected: thumbprint printed, `Algorithm = ml-dsa-65` printed, testpfx works.

- [ ] **Step 5: Commit**

```bash
git add Commands/ Pq/SignerFactory.cs
git commit -m "feat: --algorithm flag for ca command, with auto-detect for leaf signing"
```

---

### Task 4.5: Generalize ExtractKeyPair for ML-DSA

**Files:**
- Modify: `Pq/PfxExporter.cs`

The current `ExtractKeyPair` only handles RSA. ML-DSA private keys come back from PFX as opaque bytes; we need to parse them via BC's `PrivateKeyInfo`.

- [ ] **Step 1: Replace ExtractKeyPair with a multi-algorithm version**

```csharp
public static AsymmetricCipherKeyPair ExtractKeyPair(X509Certificate2 cert)
{
    // Export to PKCS#8 and re-parse via BC. This works for RSA and any PQ key
    // BC understands, because the PKCS#8 structure carries the algorithm OID.
    var rsa = cert.GetRSAPrivateKey();
    if (rsa is not null)
        return DotNetUtilities.GetRsaKeyPair(rsa);

    // For non-RSA, export the entire PKCS#12 and pull the key out via BC.
    var pfxBytes = cert.Export(X509ContentType.Pkcs12, "tmp");
    var store = new Pkcs12StoreBuilder().Build();
    using var ms = new MemoryStream(pfxBytes);
    store.Load(ms, "tmp".ToCharArray());

    foreach (string alias in store.Aliases)
    {
        if (store.IsKeyEntry(alias))
        {
            var keyEntry = store.GetKey(alias);
            var bcCert = store.GetCertificate(alias).Certificate;
            return new AsymmetricCipherKeyPair(
                bcCert.GetPublicKey(), keyEntry.Key);
        }
    }
    throw new InvalidOperationException("No private key entry in PFX.");
}
```

- [ ] **Step 2: Add a test that round-trips an ML-DSA CA through PFX**

Append to `CertificateBuilderTests.cs`:

```csharp
[Fact]
public void ML_DSA_CA_roundtrips_through_PFX_and_can_sign_leaves()
{
    var caSigner = SignerFactory.Create("ml-dsa-65");
    var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "roundtrip-ca", "Pass", caSigner,
        null, null, null));

    // simulate reload from disk
    byte[] pfxBytes = caCert.Export(X509ContentType.Pfx, "Pass");
    var reloaded = new X509Certificate2(pfxBytes, "Pass",
        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

    var detectedSigner = SignerFactory.CreateForCertificate(reloaded);
    detectedSigner.Should().BeOfType<MlDsaSigner>();
    detectedSigner.LoadKeyPair(PfxExporter.ExtractKeyPair(reloaded));

    var leafSigner = SignerFactory.Create("ml-dsa-65");
    var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.Server, "leaf.example.com", "Pass", leafSigner,
        "10.0.0.3", null, new IssuerInfo(reloaded, detectedSigner)));
    leaf.Issuer.Should().Be("CN=roundtrip-ca");
}
```

- [ ] **Step 3: Run to verify pass**

```bash
dotnet test
```

- [ ] **Step 4: Commit**

```bash
git add Pq/PfxExporter.cs Certifactory.Tests/CertificateBuilderTests.cs
git commit -m "feat: ExtractKeyPair handles ML-DSA private keys via PKCS#12"
```

---

## Phase 5 — Add SLH-DSA support

### Task 5.1: Implement SlhDsaSigner

**Files:**
- Modify: `Pq/Signing.cs`
- Modify: `Certifactory.Tests/SigningTests.cs`

Mirrors the ML-DSA pattern. Use `slh_dsa_sha2_256s` (FIPS 205, small-signature variant — 7,856-byte sigs, vs 35,664 for fast variant). Conservative choice for root CAs where signing is rare and verification can absorb the cost.

- [ ] **Step 1: Write the failing test**

Append to `SigningTests.cs`:

```csharp
[Fact]
public void SlhDsaSigner_generates_keypair_and_signature_factory()
{
    var signer = new SlhDsaSigner();
    signer.GenerateKeyPair();
    signer.AlgorithmId.Should().Be("slh-dsa-256s");
    signer.KeyPair.Should().NotBeNull();
    signer.CreateSignatureFactory().Should().NotBeNull();
}

[Fact]
public void SignerFactory_creates_slh_dsa_signer()
{
    SignerFactory.Create("slh-dsa-256s").Should().BeOfType<SlhDsaSigner>();
}
```

- [ ] **Step 2: Run to verify failure**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

- [ ] **Step 3: Implement SlhDsaSigner**

Append to `Pq/Signing.cs`:

```csharp
using Org.BouncyCastle.Pqc.Crypto.SlhDsa;

public sealed class SlhDsaSigner : IPqSigner
{
    public string AlgorithmId => "slh-dsa-256s";
    public AsymmetricCipherKeyPair KeyPair { get; private set; } = null!;

    public void GenerateKeyPair()
    {
        var random = new SecureRandom();
        var gen = new SlhDsaKeyPairGenerator();
        gen.Init(new SlhDsaKeyGenerationParameters(random,
            SlhDsaParameters.slh_dsa_sha2_256s));
        KeyPair = gen.GenerateKeyPair();
    }

    public void LoadKeyPair(AsymmetricCipherKeyPair keyPair) => KeyPair = keyPair;

    public ISignatureFactory CreateSignatureFactory()
    {
        // Algorithm string used by Asn1SignatureFactory for SLH-DSA-SHA2-256s.
        // Verified by Task 0.2 spike — adjust here if the spike found a different name.
        return new Asn1SignatureFactory("SLH-DSA-SHA2-256S", KeyPair.Private, new SecureRandom());
    }
}
```

Update SignerFactory:

```csharp
public const string SlhDsa256s = "slh-dsa-256s";

public static IPqSigner Create(string algorithmId) => algorithmId switch
{
    Rsa4096 => new RsaSigner(),
    MlDsa65 => new MlDsaSigner(),
    SlhDsa256s => new SlhDsaSigner(),
    _ => throw new ArgumentException(
        $"Unknown signing algorithm: {algorithmId}", nameof(algorithmId))
};

public static IReadOnlyList<string> SupportedAlgorithms
    => new[] { Rsa4096, MlDsa65, SlhDsa256s };
```

Add SLH-DSA OID to `CreateForCertificate` (FIPS 205: `2.16.840.1.101.3.4.3.20` for slh-dsa-sha2-256s):

```csharp
"2.16.840.1.101.3.4.3.20" => new SlhDsaSigner(),
```

- [ ] **Step 4: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

Expected: 8 passing.

- [ ] **Step 5: Commit**

```bash
git add Pq/Signing.cs Pq/SignerFactory.cs Certifactory.Tests/SigningTests.cs
git commit -m "feat: SlhDsaSigner using BouncyCastle SLH-DSA-SHA2-256s"
```

---

### Task 5.2: SLH-DSA root CA + chain test

**Files:**
- Modify: `Certifactory.Tests/CertificateBuilderTests.cs`

- [ ] **Step 1: Write the test**

```csharp
[Fact]
public void SLH_DSA_root_CA_can_sign_an_SLH_DSA_leaf()
{
    var caSigner = SignerFactory.Create("slh-dsa-256s");
    var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "slh-test-ca", "Pass", caSigner,
        null, null, null));

    caCert.SignatureAlgorithm.Value.Should().Be("2.16.840.1.101.3.4.3.20");

    var leafSigner = SignerFactory.Create("slh-dsa-256s");
    var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.Server, "slh.example.com", "Pass", leafSigner,
        "10.0.0.4", null, new IssuerInfo(caCert, caSigner)));
    leaf.Issuer.Should().Be("CN=slh-test-ca");
}
```

- [ ] **Step 2: Run to verify pass**

```bash
dotnet test
```

- [ ] **Step 3: Commit**

```bash
git add Certifactory.Tests/CertificateBuilderTests.cs
git commit -m "test: SLH-DSA root CA signs SLH-DSA leaf cert"
```

---

## Phase 6 — Hybrid certificates (backward-compatible alt-sig)

This is the most intricate phase. Read this section in full before starting.

### Background — what we're encoding

X.509:2019 Annex defines three non-critical extensions for carrying an alternative signature alongside the primary one:

| Name | OID | Contents |
|---|---|---|
| subjectAltPublicKeyInfo | 2.5.29.72 | The alt public key, encoded as `SubjectPublicKeyInfo` (same structure as primary `subjectPublicKeyInfo`) |
| altSignatureAlgorithm | 2.5.29.73 | An `AlgorithmIdentifier` for the alt signature |
| altSignatureValue | 2.5.29.74 | A `BIT STRING` containing the alt signature bytes |

**Signing process (precise):**

1. Construct a `TBSCertificate` containing all "normal" extensions plus `subjectAltPublicKeyInfo` and `altSignatureAlgorithm` — but **not** `altSignatureValue`.
2. DER-encode this partial TBS, hash it as required by the alt signer, sign with the alt private key. Result = alt signature bytes.
3. Add `altSignatureValue` extension to the TBS (carrying the alt sig as BIT STRING).
4. DER-encode the now-complete TBS, sign with the **primary** private key. Result = primary signature.
5. Final cert = `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }` where signatureAlgorithm matches the primary algorithm and signatureValue is the primary sig.

**Verification:**
- Legacy verifier: ignores the three unknown non-critical extensions, validates primary sig against tbsCertificate as it sees it. Works.
- PQ-aware verifier: extracts the three extensions, removes `altSignatureValue` from a copy of TBS, verifies alt sig over that reconstructed pre-TBS using the alt public key from `subjectAltPublicKeyInfo`.

**Why BC's `X509V3CertificateGenerator` is insufficient:** it builds TBS + signs in one pass. For hybrid we need two passes with the TBS partially built between them. We will manually construct `TbsCertificateStructure` and `X509CertificateStructure`.

### Task 6.1: Implement HybridExtensions encoder

**Files:**
- Create: `Pq/HybridExtensions.cs`
- Create: `Certifactory.Tests/HybridExtensionsTests.cs`

- [ ] **Step 1: Write the failing test**

Create `Certifactory.Tests/HybridExtensionsTests.cs`:

```csharp
using FluentAssertions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Soverance.Certifactory.Pq;
using Xunit;

namespace Certifactory.Tests;

public class HybridExtensionsTests
{
    [Fact]
    public void BuildSubjectAltPublicKeyInfo_emits_SPKI_with_correct_OID()
    {
        var altSigner = SignerFactory.Create("ml-dsa-65");
        altSigner.GenerateKeyPair();

        Asn1Encodable spki = HybridExtensions.BuildSubjectAltPublicKeyInfo(altSigner);
        var seq = (Asn1Sequence)spki.ToAsn1Object();
        seq.Count.Should().Be(2);

        var algId = AlgorithmIdentifier.GetInstance(seq[0]);
        algId.Algorithm.Id.Should().Be("2.16.840.1.101.3.4.3.18"); // ML-DSA-65
    }

    [Fact]
    public void BuildAltSignatureAlgorithm_emits_AlgorithmIdentifier()
    {
        var altSigner = SignerFactory.Create("ml-dsa-65");
        altSigner.GenerateKeyPair();
        AlgorithmIdentifier algId = HybridExtensions.BuildAltSignatureAlgorithm(altSigner);
        algId.Algorithm.Id.Should().Be("2.16.840.1.101.3.4.3.18");
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
dotnet test --filter "FullyQualifiedName~HybridExtensionsTests"
```

- [ ] **Step 3: Implement HybridExtensions skeleton**

Create `Pq/HybridExtensions.cs`:

```csharp
namespace Soverance.Certifactory.Pq;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

public static class HybridExtensions
{
    // X.509:2019 alt-extension OIDs
    public static readonly DerObjectIdentifier SubjectAltPublicKeyInfoOid =
        new DerObjectIdentifier("2.5.29.72");
    public static readonly DerObjectIdentifier AltSignatureAlgorithmOid =
        new DerObjectIdentifier("2.5.29.73");
    public static readonly DerObjectIdentifier AltSignatureValueOid =
        new DerObjectIdentifier("2.5.29.74");

    public static SubjectPublicKeyInfo BuildSubjectAltPublicKeyInfo(IPqSigner altSigner)
    {
        return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(altSigner.KeyPair.Public);
    }

    public static AlgorithmIdentifier BuildAltSignatureAlgorithm(IPqSigner altSigner)
    {
        // Re-use SubjectPublicKeyInfo's algorithm field — the alt sig algorithm
        // is the signing algorithm tied to the alt public key.
        var spki = BuildSubjectAltPublicKeyInfo(altSigner);
        return spki.AlgorithmID;
    }

    public static DerBitString BuildAltSignatureValue(byte[] sigBytes)
    {
        return new DerBitString(sigBytes);
    }
}
```

- [ ] **Step 4: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~HybridExtensionsTests"
```

Expected: 2 passing.

- [ ] **Step 5: Commit**

```bash
git add Pq/HybridExtensions.cs Certifactory.Tests/HybridExtensionsTests.cs
git commit -m "feat: encode subjectAltPublicKeyInfo and altSignatureAlgorithm extensions"
```

---

### Task 6.2: Implement HybridSigner (composed RSA + ML-DSA)

**Files:**
- Modify: `Pq/Signing.cs`
- Modify: `Certifactory.Tests/SigningTests.cs`

- [ ] **Step 1: Write the failing test**

Append to `SigningTests.cs`:

```csharp
[Fact]
public void HybridSigner_holds_primary_and_alt_signers()
{
    var primary = new RsaSigner();
    primary.GenerateKeyPair();
    var alt = new MlDsaSigner();
    alt.GenerateKeyPair();

    var hybrid = new HybridSigner(primary, alt);
    hybrid.AlgorithmId.Should().Be("hybrid");
    hybrid.PrimarySigner.Should().BeSameAs(primary);
    hybrid.AltSigner.Should().BeSameAs(alt);
}

[Fact]
public void SignerFactory_creates_hybrid_RSA_plus_ML_DSA_signer()
{
    var s = SignerFactory.Create("hybrid");
    s.Should().BeOfType<HybridSigner>();
    var h = (HybridSigner)s;
    h.PrimarySigner.Should().BeOfType<RsaSigner>();
    h.AltSigner.Should().BeOfType<MlDsaSigner>();
}
```

- [ ] **Step 2: Implement HybridSigner**

Append to `Pq/Signing.cs`:

```csharp
public sealed class HybridSigner : IPqSigner
{
    public IPqSigner PrimarySigner { get; }
    public IPqSigner AltSigner { get; }

    public HybridSigner(IPqSigner primary, IPqSigner alt)
    {
        PrimarySigner = primary;
        AltSigner = alt;
    }

    public string AlgorithmId => "hybrid";

    // KeyPair returns the PRIMARY keypair so the cert's SubjectPublicKeyInfo
    // is the classical key (the alt key goes in subjectAltPublicKeyInfo).
    public AsymmetricCipherKeyPair KeyPair => PrimarySigner.KeyPair;

    public void GenerateKeyPair()
    {
        PrimarySigner.GenerateKeyPair();
        AltSigner.GenerateKeyPair();
    }

    public void LoadKeyPair(AsymmetricCipherKeyPair keyPair)
        => throw new NotSupportedException(
            "HybridSigner requires loading both primary and alt key pairs separately.");

    public ISignatureFactory CreateSignatureFactory() => PrimarySigner.CreateSignatureFactory();
}
```

Update SignerFactory:

```csharp
public const string Hybrid = "hybrid";

public static IPqSigner Create(string algorithmId) => algorithmId switch
{
    Rsa4096 => new RsaSigner(),
    MlDsa65 => new MlDsaSigner(),
    SlhDsa256s => new SlhDsaSigner(),
    Hybrid => new HybridSigner(new RsaSigner(), new MlDsaSigner()),
    _ => throw new ArgumentException(
        $"Unknown signing algorithm: {algorithmId}", nameof(algorithmId))
};

public static IReadOnlyList<string> SupportedAlgorithms
    => new[] { Rsa4096, MlDsa65, SlhDsa256s, Hybrid };
```

- [ ] **Step 3: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~SigningTests"
```

Expected: 10 passing.

- [ ] **Step 4: Commit**

```bash
git add Pq/Signing.cs Certifactory.Tests/SigningTests.cs
git commit -m "feat: HybridSigner composing RSA + ML-DSA"
```

---

### Task 6.3: Manually build hybrid TBS with two-pass signing

**Files:**
- Modify: `Pq/HybridExtensions.cs`
- Modify: `Pq/CertificateBuilder.cs`

This is the central task of Phase 6. Read carefully before implementing.

- [ ] **Step 1: Add `HybridCertificateBuilder` helper**

A hybrid leaf cert involves four keys: subject primary (→ SPKI), subject alt (→ subjectAltPublicKeyInfo), issuer primary (signs final TBS), issuer alt (signs pre-TBS). For a self-signed root CA, subject == issuer, so the same signers are passed twice.

Append to `Pq/HybridExtensions.cs`:

```csharp
using System.Collections;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.X509;

public static class HybridCertificateBuilder
{
    /// <summary>
    /// Builds a hybrid X.509 cert with classical primary signature and PQ
    /// alt signature embedded as non-critical X.509:2019 extensions. Legacy
    /// verifiers see a normal classical cert; PQ-aware verifiers can validate
    /// the alt chain.
    ///
    /// Subject signers contribute the public keys (SPKI + subjectAltPublicKeyInfo).
    /// Issuer signers actually sign. For self-signed certs, subject == issuer.
    /// </summary>
    public static Org.BouncyCastle.X509.X509Certificate Build(
        IPqSigner subjectPrimarySigner,
        IPqSigner subjectAltSigner,
        IPqSigner issuerPrimarySigner,
        IPqSigner issuerAltSigner,
        X509Name subject,
        X509Name issuer,
        Org.BouncyCastle.Math.BigInteger serial,
        DateTime notBefore,
        DateTime notAfter,
        IList<(DerObjectIdentifier oid, bool critical, Asn1Encodable value)> normalExtensions)
    {
        // ----- step 1: build TBS WITH alt-pub-key + alt-algo extensions but
        //               WITHOUT alt-sig-value
        var allExtsForAltSig = new List<(DerObjectIdentifier, bool, Asn1Encodable)>(normalExtensions);
        allExtsForAltSig.Add((HybridExtensions.SubjectAltPublicKeyInfoOid, false,
            HybridExtensions.BuildSubjectAltPublicKeyInfo(subjectAltSigner)));
        allExtsForAltSig.Add((HybridExtensions.AltSignatureAlgorithmOid, false,
            HybridExtensions.BuildAltSignatureAlgorithm(issuerAltSigner)));

        TbsCertificateStructure preTbs = BuildTbs(
            subjectPrimarySigner, issuerPrimarySigner,
            subject, issuer, serial, notBefore, notAfter, allExtsForAltSig);

        // ----- step 2: sign preTbs with issuer's alt key
        byte[] altSig = SignBytes(issuerAltSigner, preTbs.GetDerEncoded());

        // ----- step 3: build final TBS with all three alt extensions
        var finalExts = new List<(DerObjectIdentifier, bool, Asn1Encodable)>(allExtsForAltSig);
        finalExts.Add((HybridExtensions.AltSignatureValueOid, false,
            HybridExtensions.BuildAltSignatureValue(altSig)));

        TbsCertificateStructure finalTbs = BuildTbs(
            subjectPrimarySigner, issuerPrimarySigner,
            subject, issuer, serial, notBefore, notAfter, finalExts);

        // ----- step 4: sign final TBS with issuer's primary key
        byte[] primarySig = SignBytes(issuerPrimarySigner, finalTbs.GetDerEncoded());

        // ----- step 5: assemble Certificate ::= SEQUENCE { tbs, sigAlg, sigVal }
        // sigAlg = the issuer's primary algorithm (matches what produced primarySig)
        var sigAlg = SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(issuerPrimarySigner.KeyPair.Public).AlgorithmID;
        var certSeq = new DerSequence(
            finalTbs,
            sigAlg,
            new DerBitString(primarySig));
        var certStruct = X509CertificateStructure.GetInstance(certSeq);
        return new Org.BouncyCastle.X509.X509Certificate(certStruct);
    }

    private static TbsCertificateStructure BuildTbs(
        IPqSigner subjectPrimarySigner,
        IPqSigner issuerPrimarySigner,
        X509Name subject,
        X509Name issuer,
        Org.BouncyCastle.Math.BigInteger serial,
        DateTime notBefore,
        DateTime notAfter,
        IList<(DerObjectIdentifier, bool, Asn1Encodable)> extensions)
    {
        // Subject's public key populates the cert's standard SubjectPublicKeyInfo
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
            subjectPrimarySigner.KeyPair.Public);

        // tbs.signature must equal the algorithm of whoever actually signs
        // the TBS — i.e. the issuer's primary algorithm
        var tbsSigAlgId = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
            issuerPrimarySigner.KeyPair.Public).AlgorithmID;

        var extDict = new Hashtable();
        var extOrder = new ArrayList();
        foreach (var (oid, critical, val) in extensions)
        {
            extOrder.Add(oid);
            extDict[oid] = new X509Extension(critical, new DerOctetString(val.GetDerEncoded()));
        }
        var x509Extensions = new X509Extensions(extOrder, extDict);

        var tbsGen = new V3TbsCertificateGenerator();
        tbsGen.SetSerialNumber(new DerInteger(serial));
        tbsGen.SetIssuer(issuer);
        tbsGen.SetSubject(subject);
        tbsGen.SetStartDate(new Time(notBefore));
        tbsGen.SetEndDate(new Time(notAfter));
        tbsGen.SetSignature(tbsSigAlgId);
        tbsGen.SetSubjectPublicKeyInfo(spki);
        tbsGen.SetExtensions(x509Extensions);
        return tbsGen.GenerateTbsCertificate();
    }

    private static byte[] SignBytes(IPqSigner signer, byte[] data)
    {
        var streamCalc = signer.CreateSignatureFactory()
            .CreateCalculator();
        using (var s = streamCalc.Stream)
        {
            s.Write(data, 0, data.Length);
        }
        return ((IBlockResult)streamCalc.GetResult()).Collect();
    }
}
```

- [ ] **Step 2: Refactor CertificateBuilder to share an extension list, and dispatch to hybrid path**

The previous `AddCommonExtensions(gen, spec)` mutated the generator directly. Replace it with `CollectExtensions(spec)` which returns a list, then have both paths walk that list. This avoids double-maintenance.

Replace the body of `Pq/CertificateBuilder.cs` with:

```csharp
namespace Soverance.Certifactory.Pq;

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

public enum CertificatePurpose { RootCa, Server, Smime }

public sealed record CertificateSpec(
    CertificatePurpose Purpose,
    string CommonName,
    string Password,
    IPqSigner Signer,
    string? ServerIp,
    string? EmailAddress,
    IssuerInfo? Issuer);

public sealed record IssuerInfo(
    X509Certificate2 Certificate,
    IPqSigner Signer);

public static class CertificateBuilder
{
    public static X509Certificate2 BuildCertificate(CertificateSpec spec)
    {
        if (spec.Signer.KeyPair is null)
            spec.Signer.GenerateKeyPair();

        Org.BouncyCastle.X509.X509Certificate bcCert =
            spec.Signer is HybridSigner h
                ? BuildHybrid(spec, h)
                : BuildSinglePass(spec);

        var keyForPfx = spec.Signer is HybridSigner hs
            ? hs.PrimarySigner.KeyPair.Private
            : spec.Signer.KeyPair.Private;

        return PfxExporter.ToX509Certificate2(
            bcCert, keyForPfx, spec.CommonName, spec.Password);
    }

    private static Org.BouncyCastle.X509.X509Certificate BuildSinglePass(CertificateSpec spec)
    {
        var random = new SecureRandom();
        var gen = new X509V3CertificateGenerator();
        var subject = BuildSubject(spec);
        var issuer = spec.Issuer is null
            ? subject
            : ParseDn(spec.Issuer.Certificate.SubjectName.Name);

        gen.SetSerialNumber(new BigInteger(159, random).Abs().Add(BigInteger.One));
        gen.SetSubjectDN(subject);
        gen.SetIssuerDN(issuer);
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(GetValidityDays(spec.Purpose)));
        gen.SetPublicKey(spec.Signer.KeyPair.Public);

        foreach (var (oid, critical, value) in CollectExtensions(spec))
        {
            gen.AddExtension(oid, critical, value);
        }

        ISignatureFactory sigFactory = spec.Issuer is null
            ? spec.Signer.CreateSignatureFactory()
            : spec.Issuer.Signer.CreateSignatureFactory();

        return gen.Generate(sigFactory);
    }

    private static Org.BouncyCastle.X509.X509Certificate BuildHybrid(
        CertificateSpec spec, HybridSigner subjectHybridSigner)
    {
        var random = new SecureRandom();
        var subject = BuildSubject(spec);
        var issuer = spec.Issuer is null
            ? subject
            : ParseDn(spec.Issuer.Certificate.SubjectName.Name);
        var serial = new BigInteger(159, random).Abs().Add(BigInteger.One);

        // Determine the issuer's hybrid signer:
        //  - self-signed root CA: subject IS the issuer
        //  - leaf cert: must be issued by a hybrid CA (so we have an alt signer too)
        HybridSigner issuerHybridSigner;
        if (spec.Issuer is null)
        {
            issuerHybridSigner = subjectHybridSigner;
        }
        else if (spec.Issuer.Signer is HybridSigner h)
        {
            issuerHybridSigner = h;
        }
        else
        {
            throw new InvalidOperationException(
                "Hybrid leaf certificates require a hybrid issuer CA. " +
                "Issue this leaf from a CA generated with --algorithm hybrid, " +
                "or use a non-hybrid algorithm for the leaf.");
        }

        var exts = CollectExtensions(spec);

        return HybridCertificateBuilder.Build(
            subjectPrimarySigner: subjectHybridSigner.PrimarySigner,
            subjectAltSigner: subjectHybridSigner.AltSigner,
            issuerPrimarySigner: issuerHybridSigner.PrimarySigner,
            issuerAltSigner: issuerHybridSigner.AltSigner,
            subject: subject,
            issuer: issuer,
            serial: serial,
            notBefore: DateTime.UtcNow.AddDays(-1),
            notAfter: DateTime.UtcNow.AddDays(GetValidityDays(spec.Purpose)),
            normalExtensions: exts);
    }

    /// <summary>
    /// Returns the per-purpose extension list as (oid, critical, value) tuples.
    /// Both BuildSinglePass and BuildHybrid consume this — keep it the only
    /// source of cert-extension truth.
    /// </summary>
    private static List<(DerObjectIdentifier oid, bool critical, Asn1Encodable value)>
        CollectExtensions(CertificateSpec spec)
    {
        var pubKey = spec.Signer is HybridSigner hs
            ? hs.PrimarySigner.KeyPair.Public
            : spec.Signer.KeyPair.Public;

        var list = new List<(DerObjectIdentifier, bool, Asn1Encodable)>();

        switch (spec.Purpose)
        {
            case CertificatePurpose.RootCa:
                list.Add((X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: true)));
                list.Add((X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign)));
                list.Add((X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(pubKey)));
                list.Add((X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(
                        KeyPurposeID.id_kp_serverAuth,
                        KeyPurposeID.id_kp_clientAuth,
                        KeyPurposeID.id_kp_codeSigning,
                        KeyPurposeID.id_kp_emailProtection,
                        new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12"))));
                break;

            case CertificatePurpose.Server:
                list.Add((X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: false)));
                list.Add((X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.DigitalSignature
                        | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment)));
                list.Add((X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(
                        KeyPurposeID.id_kp_serverAuth, KeyPurposeID.id_kp_clientAuth)));
                list.Add((X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(pubKey)));
                if (spec.Issuer is not null)
                {
                    list.Add((X509Extensions.AuthorityKeyIdentifier, false,
                        new AuthorityKeyIdentifierStructure(
                            DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate))));
                }
                list.Add((X509Extensions.SubjectAlternativeName, false,
                    BuildServerSan(spec)));
                break;

            case CertificatePurpose.Smime:
                if (string.IsNullOrEmpty(spec.EmailAddress))
                    throw new ArgumentException("S/MIME spec requires EmailAddress");
                list.Add((X509Extensions.BasicConstraints, true,
                    new BasicConstraints(cA: false)));
                list.Add((X509Extensions.KeyUsage, true,
                    new KeyUsage(KeyUsage.NonRepudiation | KeyUsage.DigitalSignature
                        | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment)));
                list.Add((X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(
                        KeyPurposeID.id_kp_emailProtection,
                        new DerObjectIdentifier("1.3.6.1.4.1.311.10.3.12"))));
                list.Add((X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(pubKey)));
                if (spec.Issuer is not null)
                {
                    list.Add((X509Extensions.AuthorityKeyIdentifier, false,
                        new AuthorityKeyIdentifierStructure(
                            DotNetUtilities.FromX509Certificate(spec.Issuer.Certificate))));
                }
                list.Add((X509Extensions.SubjectAlternativeName, false,
                    new GeneralNames(new[]
                    {
                        new GeneralName(GeneralName.Rfc822Name, spec.EmailAddress)
                    })));
                break;
        }

        return list;
    }

    private static GeneralNames BuildServerSan(CertificateSpec spec)
    {
        var names = new List<GeneralName>
        {
            new GeneralName(GeneralName.DnsName, spec.CommonName)
        };
        if (!string.IsNullOrEmpty(spec.ServerIp))
        {
            names.Add(new GeneralName(GeneralName.IPAddress, spec.ServerIp));
        }
        return new GeneralNames(names.ToArray());
    }

    private static X509Name BuildSubject(CertificateSpec spec) => spec.Purpose switch
    {
        CertificatePurpose.RootCa => new X509Name($"CN={spec.CommonName}"),
        CertificatePurpose.Server => new X509Name($"CN={spec.CommonName}"),
        CertificatePurpose.Smime  => new X509Name(
            $"CN={spec.CommonName},C=US,ST=Georgia,L=Atlanta,O=Soverance Studios,OU=Information"),
        _ => throw new ArgumentOutOfRangeException()
    };

    private static X509Name ParseDn(string dn) => new X509Name(dn);

    private static int GetValidityDays(CertificatePurpose purpose) => purpose switch
    {
        CertificatePurpose.RootCa => 7300,  // 20 years
        CertificatePurpose.Server => 396,   // iOS limit
        CertificatePurpose.Smime  => 3650,  // 10 years
        _ => 365
    };
}
```

Note: this replaces the `AddCommonExtensions`-based version from Task 3.4. The single `CollectExtensions` method now feeds both single-pass and hybrid paths.

- [ ] **Step 3: Run all tests**

```bash
dotnet test
```

Expected: existing tests still green; hybrid path not yet tested.

- [ ] **Step 4: Commit**

```bash
git add Pq/HybridExtensions.cs Pq/CertificateBuilder.cs
git commit -m "feat: hybrid cert builder with two-pass signing for alt-sig extensions"
```

---

### Task 6.4: End-to-end hybrid cert tests

**Files:**
- Modify: `Certifactory.Tests/HybridExtensionsTests.cs`

- [ ] **Step 1: Write the failing tests**

Append to `HybridExtensionsTests.cs`:

```csharp
using System.Security.Cryptography.X509Certificates;

[Fact]
public void Hybrid_root_CA_carries_three_alt_extensions()
{
    var signer = SignerFactory.Create("hybrid");
    var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "hybrid-test-ca", "Pass", signer,
        null, null, null));

    cert.Extensions.Should().Contain(e => e.Oid?.Value == "2.5.29.72"); // subjectAltPublicKeyInfo
    cert.Extensions.Should().Contain(e => e.Oid?.Value == "2.5.29.73"); // altSignatureAlgorithm
    cert.Extensions.Should().Contain(e => e.Oid?.Value == "2.5.29.74"); // altSignatureValue
}

[Fact]
public void Hybrid_cert_primary_signature_is_classical_RSA()
{
    var signer = SignerFactory.Create("hybrid");
    var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "hybrid-classical-ca", "Pass", signer,
        null, null, null));

    // Primary signature OID should be sha256WithRSAEncryption
    cert.SignatureAlgorithm.Value.Should().Be("1.2.840.113549.1.1.11");
}

[Fact]
public void Hybrid_alt_extensions_are_non_critical()
{
    var signer = SignerFactory.Create("hybrid");
    var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "hybrid-noncrit-ca", "Pass", signer,
        null, null, null));

    foreach (var ext in cert.Extensions)
    {
        if (ext.Oid?.Value is "2.5.29.72" or "2.5.29.73" or "2.5.29.74")
        {
            ext.Critical.Should().BeFalse(
                $"alt-sig extension {ext.Oid.Value} must be non-critical for legacy compat");
        }
    }
}

[Fact]
public void Hybrid_cert_legacy_RSA_validation_succeeds()
{
    // Legacy validators (anything that uses .NET's built-in X509Chain with no
    // PQC awareness) should validate the primary RSA signature successfully.
    // We can't fully prove this without running an external validator, but we
    // can at least extract the RSA pubkey and verify the primary chain works.

    var signer = SignerFactory.Create("hybrid");
    var ca = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "legacy-test-ca", "Pass", signer,
        null, null, null));

    var leafSigner = SignerFactory.Create("hybrid");
    var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.Server, "legacy.example.com", "Pass", leafSigner,
        "10.0.0.5", null, new IssuerInfo(ca, signer)));

    // The leaf's issuer name matches the CA's subject, the AKI should match
    // the CA's SKI, and the primary RSA signature on the leaf should verify
    // against the CA's RSA public key. .NET's X509Chain handles all this if
    // we install the CA into a chain policy.
    using var chain = new X509Chain();
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(ca);
    bool ok = chain.Build(leaf);

    ok.Should().BeTrue($"legacy chain build failed: {string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation))}");
}
```

- [ ] **Step 2: Run to verify pass**

```bash
dotnet test
```

If the chain test fails with `NotSignatureValid`, the issue is almost certainly in how the alt extensions are being added to TBS. Verify:
- The ORDER of extensions (BC's `X509Extensions` table preserves insertion order via the `extOrder` list).
- That the primary signature was computed over the FINAL TBS (all three alt extensions present), not the partial one.
- That the `signature` field of TBS matches the primary signature algorithm in the outer Certificate.

- [ ] **Step 3: Commit**

```bash
git add Certifactory.Tests/HybridExtensionsTests.cs
git commit -m "test: hybrid CA emits three alt extensions and validates as legacy RSA chain"
```

---

### Task 6.5: PQ-aware alt-sig verification test

**Files:**
- Modify: `Certifactory.Tests/HybridExtensionsTests.cs`
- Modify: `Pq/HybridExtensions.cs`

A PQ-aware verifier needs to:
1. Read `subjectAltPublicKeyInfo` extension to get the alt public key.
2. Read `altSignatureValue` extension for the alt sig.
3. Reconstruct the pre-TBS by removing only the `altSignatureValue` extension.
4. Verify the alt sig over that reconstructed pre-TBS using the alt public key.

We will implement a verifier helper in `HybridExtensions` and test it.

- [ ] **Step 1: Add `VerifyAltSignature` helper**

Append to `Pq/HybridExtensions.cs`:

```csharp
using Org.BouncyCastle.Crypto.Operators;

public static class HybridVerifier
{
    /// <summary>
    /// Verifies the alt signature on a hybrid certificate by reconstructing
    /// the pre-TBS (TBS minus altSignatureValue) and validating against the
    /// alt public key from subjectAltPublicKeyInfo.
    /// </summary>
    public static bool VerifyAltSignature(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        // Parse the cert via BC so we can access TBS structure
        var bcCert = DotNetUtilities.FromX509Certificate(cert);
        var tbs = bcCert.CertificateStructure.TbsCertificate;

        // Pull the three alt extensions
        var spkiBytes = bcCert.GetExtensionValue(HybridExtensions.SubjectAltPublicKeyInfoOid);
        var algIdBytes = bcCert.GetExtensionValue(HybridExtensions.AltSignatureAlgorithmOid);
        var sigValBytes = bcCert.GetExtensionValue(HybridExtensions.AltSignatureValueOid);
        if (spkiBytes is null || algIdBytes is null || sigValBytes is null)
            return false;

        var altSpki = SubjectPublicKeyInfo.GetInstance(
            Asn1Object.FromByteArray(spkiBytes.GetOctets()));
        var altAlg = AlgorithmIdentifier.GetInstance(
            Asn1Object.FromByteArray(algIdBytes.GetOctets()));
        var altSigBits = DerBitString.GetInstance(
            Asn1Object.FromByteArray(sigValBytes.GetOctets()));

        // Reconstruct preTBS = TBS with altSignatureValue removed
        byte[] preTbsDer = ReconstructPreTbsForAltSig(tbs);

        // Verify with BC's PublicKeyFactory
        var altPublicKey = PublicKeyFactory.CreateKey(altSpki);
        var verifier = new Asn1VerifierFactory(altAlg.Algorithm.Id, altPublicKey);
        var calc = verifier.CreateCalculator();
        using (var s = calc.Stream)
        {
            s.Write(preTbsDer, 0, preTbsDer.Length);
        }
        return ((IVerifier)calc.GetResult()).IsVerified(altSigBits.GetBytes());
    }

    private static byte[] ReconstructPreTbsForAltSig(TbsCertificateStructure tbs)
    {
        // Walk extensions, drop the one with OID 2.5.29.74, re-encode TBS.
        var origExts = tbs.Extensions;
        var newOrder = new ArrayList();
        var newDict = new Hashtable();
        foreach (DerObjectIdentifier oid in origExts.ExtensionOids)
        {
            if (oid.Equals(HybridExtensions.AltSignatureValueOid)) continue;
            newOrder.Add(oid);
            newDict[oid] = origExts.GetExtension(oid);
        }
        var newExts = new X509Extensions(newOrder, newDict);

        var tbsGen = new V3TbsCertificateGenerator();
        tbsGen.SetSerialNumber(tbs.SerialNumber);
        tbsGen.SetIssuer(tbs.Issuer);
        tbsGen.SetSubject(tbs.Subject);
        tbsGen.SetStartDate(tbs.StartDate);
        tbsGen.SetEndDate(tbs.EndDate);
        tbsGen.SetSignature(tbs.Signature);
        tbsGen.SetSubjectPublicKeyInfo(tbs.SubjectPublicKeyInfo);
        tbsGen.SetExtensions(newExts);
        return tbsGen.GenerateTbsCertificate().GetDerEncoded();
    }
}
```

- [ ] **Step 2: Write the test**

Append to `HybridExtensionsTests.cs`:

```csharp
[Fact]
public void Hybrid_cert_alt_signature_verifies_against_alt_public_key()
{
    var signer = SignerFactory.Create("hybrid");
    var cert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "verify-alt-ca", "Pass", signer,
        null, null, null));

    HybridVerifier.VerifyAltSignature(cert).Should().BeTrue();
}
```

- [ ] **Step 3: Run to verify pass**

```bash
dotnet test --filter "FullyQualifiedName~HybridExtensionsTests"
```

If verification fails, the most likely cause is encoding mismatch in `ReconstructPreTbsForAltSig` — the byte representation of the reconstructed TBS must exactly match what was signed in Task 6.3 step 1 (preTbs with subjectAltPublicKeyInfo + altSignatureAlgorithm but without altSignatureValue). Add a debug assertion that compares the byte length of the reconstructed pre-TBS against what was signed; if they differ, walk the extension order.

- [ ] **Step 4: Commit**

```bash
git add Pq/HybridExtensions.cs Certifactory.Tests/HybridExtensionsTests.cs
git commit -m "feat: HybridVerifier reconstructs preTBS and validates alt signature"
```

---

### Task 6.6: Hybrid CA → hybrid leaf chain test (full proof of concept)

**Files:**
- Modify: `Certifactory.Tests/HybridExtensionsTests.cs`

- [ ] **Step 1: Write the test**

```csharp
[Fact]
public void Hybrid_leaf_chain_validates_under_both_classical_and_PQ_paths()
{
    var caSigner = SignerFactory.Create("hybrid");
    var ca = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "hybrid-chain-ca", "Pass", caSigner,
        null, null, null));

    var leafSigner = SignerFactory.Create("hybrid");
    var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.Server, "hybrid-leaf.example.com", "Pass", leafSigner,
        "10.0.0.6", null, new IssuerInfo(ca, caSigner)));

    // Classical path: legacy X509Chain
    using var chain = new X509Chain();
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(ca);
    chain.Build(leaf).Should().BeTrue();

    // PQ alt-sig path: verify both ca and leaf alt sigs
    HybridVerifier.VerifyAltSignature(ca).Should().BeTrue();
    HybridVerifier.VerifyAltSignature(leaf).Should().BeTrue();
}
```

- [ ] **Step 2: Run to verify pass**

```bash
dotnet test
```

This is the core demo: a hybrid leaf cert validates as a normal RSA chain AND its alt PQ signature is verifiable. If both pass, hybrid mode is functionally correct.

- [ ] **Step 3: Commit**

```bash
git add Certifactory.Tests/HybridExtensionsTests.cs
git commit -m "test: hybrid leaf chain validates under both classical and PQ paths"
```

---

### Task 6.7: Persist alt private key in PFX

**Files:**
- Modify: `Pq/PfxExporter.cs`
- Modify: `Pq/CertificateBuilder.cs`

A hybrid CA cannot issue leaves later if its alt private key isn't persisted. PKCS#12 supports multiple key entries per file — we'll store the alt key under a `<alias>-alt` alias.

- [ ] **Step 1: Update `PfxExporter.ToX509Certificate2` to optionally store an alt key**

Replace the body of `ToX509Certificate2` in `Pq/PfxExporter.cs`:

```csharp
public static X509Certificate2 ToX509Certificate2(
    Org.BouncyCastle.X509.X509Certificate bcCert,
    AsymmetricKeyParameter privateKey,
    string friendlyName,
    string password,
    AsymmetricKeyParameter? altPrivateKey = null)
{
    var store = new Pkcs12StoreBuilder().Build();
    var certEntry = new X509CertificateEntry(bcCert);
    store.SetCertificateEntry(friendlyName, certEntry);
    store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey),
        new[] { certEntry });
    if (altPrivateKey is not null)
    {
        store.SetKeyEntry(friendlyName + "-alt",
            new AsymmetricKeyEntry(altPrivateKey),
            new[] { certEntry });
    }

    using var ms = new MemoryStream();
    store.Save(ms, password.ToCharArray(), new SecureRandom());
    return new X509Certificate2(ms.ToArray(), password,
        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
}
```

- [ ] **Step 2: Update CertificateBuilder.BuildCertificate to pass the alt key**

Replace the BuildCertificate method body in `Pq/CertificateBuilder.cs`:

```csharp
public static X509Certificate2 BuildCertificate(CertificateSpec spec)
{
    if (spec.Signer.KeyPair is null)
        spec.Signer.GenerateKeyPair();

    Org.BouncyCastle.X509.X509Certificate bcCert =
        spec.Signer is HybridSigner h
            ? BuildHybrid(spec, h)
            : BuildSinglePass(spec);

    AsymmetricKeyParameter primaryKey;
    AsymmetricKeyParameter? altKey;
    if (spec.Signer is HybridSigner hs)
    {
        primaryKey = hs.PrimarySigner.KeyPair.Private;
        altKey = hs.AltSigner.KeyPair.Private;
    }
    else
    {
        primaryKey = spec.Signer.KeyPair.Private;
        altKey = null;
    }

    return PfxExporter.ToX509Certificate2(
        bcCert, primaryKey, spec.CommonName, spec.Password, altKey);
}
```

- [ ] **Step 3: Verify existing tests still pass**

```bash
dotnet test
```

Expected: all green. The non-hybrid path still passes `null` for the alt key, so behavior is unchanged.

- [ ] **Step 4: Commit**

```bash
git add Pq/PfxExporter.cs Pq/CertificateBuilder.cs
git commit -m "feat: persist alt private key in PFX for hybrid certs"
```

---

### Task 6.8: Detect hybrid certs and load both keys on reload

**Files:**
- Modify: `Pq/PfxExporter.cs`
- Modify: `Pq/Signing.cs` (SignerFactory.CreateForCertificate)
- Modify: `Commands/ServerCommand.cs`
- Modify: `Commands/SmimeCommand.cs`
- Modify: `Certifactory.Tests/CertificateBuilderTests.cs`

- [ ] **Step 1: Write the failing roundtrip test**

Append to `CertificateBuilderTests.cs`:

```csharp
[Fact]
public void Hybrid_CA_roundtrips_through_PFX_and_can_issue_hybrid_leaves()
{
    // generate hybrid CA, export to PFX, reload, issue hybrid leaf.
    var caSigner = SignerFactory.Create("hybrid");
    var caCert = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.RootCa, "hybrid-roundtrip-ca", "Pass", caSigner,
        null, null, null));

    byte[] pfxBytes = caCert.Export(X509ContentType.Pfx, "Pass");
    var reloaded = new X509Certificate2(pfxBytes, "Pass",
        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

    var detectedSigner = SignerFactory.CreateForCertificate(reloaded);
    detectedSigner.Should().BeOfType<HybridSigner>();

    var hybridDetected = (HybridSigner)detectedSigner;
    var (primary, alt) = PfxExporter.ExtractHybridKeyPairs(reloaded);
    alt.Should().NotBeNull();
    hybridDetected.PrimarySigner.LoadKeyPair(primary);
    hybridDetected.AltSigner.LoadKeyPair(alt!);

    var leafSigner = SignerFactory.Create("hybrid");
    var leaf = CertificateBuilder.BuildCertificate(new CertificateSpec(
        CertificatePurpose.Server, "hybrid-leaf.example.com", "Pass", leafSigner,
        "10.0.0.7", null, new IssuerInfo(reloaded, hybridDetected)));
    leaf.Issuer.Should().Be("CN=hybrid-roundtrip-ca");
    HybridVerifier.VerifyAltSignature(leaf).Should().BeTrue();
}
```

- [ ] **Step 2: Run to verify failure**

```bash
dotnet test --filter "FullyQualifiedName~Hybrid_CA_roundtrips"
```

Expected: compile error — `ExtractHybridKeyPairs` does not exist.

- [ ] **Step 3: Add `ExtractHybridKeyPairs` to PfxExporter**

Append to `Pq/PfxExporter.cs`:

```csharp
public static (AsymmetricCipherKeyPair primary, AsymmetricCipherKeyPair? alt)
    ExtractHybridKeyPairs(X509Certificate2 cert)
{
    // Re-export to a temporary PFX so we can walk it via BC's Pkcs12Store.
    // We need this even for plain RSA because GetRSAPrivateKey() doesn't
    // expose multiple key entries.
    var pfxBytes = cert.Export(X509ContentType.Pkcs12, "tmp");
    var store = new Pkcs12StoreBuilder().Build();
    using var ms = new MemoryStream(pfxBytes);
    store.Load(ms, "tmp".ToCharArray());

    AsymmetricCipherKeyPair? primary = null;
    AsymmetricKeyParameter? altPrivate = null;

    // First pass: locate primary cert + primary private key
    Org.BouncyCastle.X509.X509Certificate? bcCert = null;
    foreach (string alias in store.Aliases)
    {
        if (store.IsKeyEntry(alias) && !alias.EndsWith("-alt"))
        {
            var keyEntry = store.GetKey(alias);
            bcCert = store.GetCertificate(alias).Certificate;
            primary = new AsymmetricCipherKeyPair(bcCert.GetPublicKey(), keyEntry.Key);
        }
    }
    // Second pass: locate alt private key
    foreach (string alias in store.Aliases)
    {
        if (store.IsKeyEntry(alias) && alias.EndsWith("-alt"))
        {
            altPrivate = store.GetKey(alias).Key;
        }
    }

    if (primary is null)
        throw new InvalidOperationException("No primary private key entry in PFX.");

    AsymmetricCipherKeyPair? alt = null;
    if (altPrivate is not null)
    {
        // Pull the alt public key from the cert's subjectAltPublicKeyInfo extension
        var altSpkiBytes = bcCert!.GetExtensionValue(
            HybridExtensions.SubjectAltPublicKeyInfoOid);
        if (altSpkiBytes is not null)
        {
            var altSpki = SubjectPublicKeyInfo.GetInstance(
                Asn1Object.FromByteArray(altSpkiBytes.GetOctets()));
            var altPublic = PublicKeyFactory.CreateKey(altSpki);
            alt = new AsymmetricCipherKeyPair(altPublic, altPrivate);
        }
    }

    return (primary, alt);
}
```

(Add `using Org.BouncyCastle.Asn1;` and `using Org.BouncyCastle.Asn1.X509;` to PfxExporter.cs.)

- [ ] **Step 4: Update CreateForCertificate to detect hybrid via the alt extension**

Replace the `CreateForCertificate` method in `Pq/Signing.cs`:

```csharp
public static IPqSigner CreateForCertificate(
    System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
{
    bool isHybrid = cert.Extensions.Any(e => e.Oid?.Value == "2.5.29.72");

    if (isHybrid)
    {
        var primary = CreateByOid(cert.SignatureAlgorithm.Value!);

        // Read the alt algorithm OID from the altSignatureAlgorithm extension
        var altAlgExt = cert.Extensions.First(e => e.Oid?.Value == "2.5.29.73");
        var altAlgOid = ReadAlgorithmIdentifierOid(altAlgExt.RawData);
        var alt = CreateByOid(altAlgOid);

        return new HybridSigner(primary, alt);
    }
    return CreateByOid(cert.SignatureAlgorithm.Value!);
}

private static IPqSigner CreateByOid(string oid) => oid switch
{
    "1.2.840.113549.1.1.11" => new RsaSigner(),
    "2.16.840.1.101.3.4.3.18" => new MlDsaSigner(),
    "2.16.840.1.101.3.4.3.20" => new SlhDsaSigner(),
    _ => throw new NotSupportedException($"Unknown algorithm OID: {oid}")
};

private static string ReadAlgorithmIdentifierOid(byte[] extensionRawValue)
{
    // The extension RawData is the wrapping OCTET STRING; inside is an
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY }.
    var asn1 = Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(extensionRawValue);
    var algId = Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier.GetInstance(asn1);
    return algId.Algorithm.Id;
}
```

(Add `using System.Linq;` at the top of `Pq/Signing.cs` if not already present.)

- [ ] **Step 5: Update ServerCommand handler to use the hybrid loading path**

In `Commands/ServerCommand.cs`, replace the `caSigner` block inside `SetHandler` with:

```csharp
var caSigner = Pq.SignerFactory.CreateForCertificate(caCert);
var (primaryKp, altKp) = Pq.PfxExporter.ExtractHybridKeyPairs(caCert);
if (caSigner is Pq.HybridSigner caHybrid)
{
    if (altKp is null)
        throw new InvalidOperationException(
            "Hybrid CA PFX is missing its alt private key. " +
            "Was it generated with a pre-hybrid version of Certifactory?");
    caHybrid.PrimarySigner.LoadKeyPair(primaryKp);
    caHybrid.AltSigner.LoadKeyPair(altKp);
}
else
{
    caSigner.LoadKeyPair(primaryKp);
}
```

Apply the identical change to `Commands/SmimeCommand.cs`.

- [ ] **Step 6: Run tests to verify pass**

```bash
dotnet test
```

Expected: all green, including the new roundtrip test.

- [ ] **Step 7: Commit**

```bash
git add Pq/PfxExporter.cs Pq/Signing.cs Commands/ServerCommand.cs Commands/SmimeCommand.cs Certifactory.Tests/CertificateBuilderTests.cs
git commit -m "feat: detect hybrid certs on PFX reload, load both private keys"
```

---

### Task 6.9: CLI smoke test for `--algorithm hybrid`

**Files:** none modified — purely a manual verification step.

- [ ] **Step 1: Run all four algorithm options end to end**

```bash
mkdir -p /tmp/cert-final
dotnet run --project Certifactory.csproj -- ca rsa-ca       Pass /tmp/cert-final --algorithm rsa-4096
dotnet run --project Certifactory.csproj -- ca mldsa-ca     Pass /tmp/cert-final --algorithm ml-dsa-65
dotnet run --project Certifactory.csproj -- ca slh-ca       Pass /tmp/cert-final --algorithm slh-dsa-256s
dotnet run --project Certifactory.csproj -- ca hybrid-ca    Pass /tmp/cert-final --algorithm hybrid

# leaves
dotnet run --project Certifactory.csproj -- server srv.example.com Pass "" /tmp/cert-final/hybrid-ca.pfx Pass /tmp/cert-final --algorithm hybrid
dotnet run --project Certifactory.csproj -- smime  alice@example.com Pass alice@example.com /tmp/cert-final/hybrid-ca.pfx Pass /tmp/cert-final --algorithm hybrid
```

Expected: every command prints `Algorithm = ...` and a thumbprint, every PFX exists. PFX file sizes for hybrid certs will be noticeably larger than RSA-only (additional ~3.5KB for ML-DSA alt key + sig).

- [ ] **Step 2: Inspect a hybrid cert with OpenSSL (sanity check)**

```bash
openssl pkcs12 -in /tmp/cert-final/hybrid-ca.pfx -passin pass:Pass -nokeys -out /tmp/cert-final/hybrid-ca.pem
openssl x509 -in /tmp/cert-final/hybrid-ca.pem -text -noout | grep -A2 "X509v3 extensions"
```

Expected: extension list shows OIDs 2.5.29.72 / 73 / 74. OpenSSL will print them as "Unknown extension" (it doesn't render the names) but they should be present.

- [ ] **Step 3: Commit (no code changes — just a marker)**

If the smoke test required no fixes, no commit is needed; if it surfaced bugs, commit each fix individually and re-run.

---

## Phase 7 — Documentation

### Task 7.1: Update README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add an algorithm comparison section**

Add a new section near the top of `README.md`, before the existing `# Commands` heading:

```markdown
# Algorithm options

The `ca`, `server`, and `smime` commands accept an `--algorithm` flag:

| Value | Description | When to use |
|---|---|---|
| `rsa-4096` (default) | Classical RSA-4096 with SHA-256 | Maximum compatibility — every existing client trusts it |
| `ml-dsa-65` | FIPS 204 ML-DSA-65 (post-quantum lattice signatures) | Internal-only deployments where you control all clients and want pure PQC |
| `slh-dsa-256s` | FIPS 205 SLH-DSA-SHA2-256s (hash-based) | Long-lived offline root CAs where signature size doesn't matter and conservative security assumptions are paramount |
| `hybrid` | RSA-4096 primary + ML-DSA-65 alt-signature (X.509:2019 alt-sig extensions) | Production deployments — legacy clients see classical RSA, PQ-aware clients can validate the alt chain |

**Hybrid certificates** use non-critical X.509 extensions (`subjectAltPublicKeyInfo` 2.5.29.72, `altSignatureAlgorithm` 2.5.29.73, `altSignatureValue` 2.5.29.74) to embed a second signature alongside the classical one. Verifiers that don't understand these extensions ignore them and validate the cert as a normal RSA chain.
```

- [ ] **Step 2: Update each command block to mention `--algorithm`**

In the `ca`, `server`, and `smime` sections of the README, change the command syntax to include `[--algorithm <name>]` and add a row to the parameter table:

```markdown
| `--algorithm` | (Optional) Signing algorithm: `rsa-4096` (default), `ml-dsa-65`, `slh-dsa-256s`, `hybrid`. |
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README covers --algorithm flag and hybrid certificates"
```

---

### Task 7.2: Update per-command docs

**Files:**
- Modify: `docs/ca.md`
- Modify: `docs/server.md`
- Modify: `docs/smime.md`

- [ ] **Step 1: Add an Algorithms section to each**

For each of the three docs, add a section like:

```markdown
## Algorithm selection

Pass `--algorithm` to choose the signing algorithm. See README for the full comparison table.

Example — generate a hybrid root CA:

\`\`\`
certifactory ca my-org-root MyPass /etc/certs --algorithm hybrid
\`\`\`

Example — generate an SLH-DSA root for an air-gapped offline signing facility:

\`\`\`
certifactory ca offline-root MyPass /secure/certs --algorithm slh-dsa-256s
\`\`\`

When generating leaf certs (`server` or `smime`), the leaf's algorithm should generally match the CA's algorithm. Mixing — e.g. an RSA leaf signed by a hybrid CA — is supported (the CA's primary classical key signs the leaf), but the leaf will only have a classical signature, defeating the purpose of using a hybrid CA. For consistent post-quantum coverage, use the same algorithm at every level of the chain.
```

- [ ] **Step 2: Commit**

```bash
git add docs/ca.md docs/server.md docs/smime.md
git commit -m "docs: per-command pages document --algorithm with examples"
```

---

## Phase 8 — Final verification

### Task 8.1: Full test sweep

- [ ] **Step 1: Run all tests with verbose output**

```bash
dotnet test --logger "console;verbosity=detailed"
```

Expected: all tests pass. Catalog by category:

| Category | Expected count |
|---|---|
| `PqApiSpike` | 2 |
| `CommonTests` | 2 |
| `SigningTests` | 10 |
| `CertificateBuilderTests` | 9 |
| `HybridExtensionsTests` | 8 |

Total: 31 tests passing.

- [ ] **Step 2: Run the full CLI smoke matrix**

Use the script from Task 6.9 and verify every command produces a working PFX, every PFX passes `testpfx`, and every leaf cert correctly identifies its CA via `testpfx`'s `Issuer` line.

- [ ] **Step 3: Confirm BouncyCastle is the only third-party dependency**

```bash
grep -E "PackageReference" Certifactory.csproj
```

Expected output: only `BouncyCastle.Cryptography` and `System.CommandLine`.

---

### Task 8.2: Cleanup

- [ ] **Step 1: Remove the temporary `UnitTest1.cs` from xunit template**

```bash
rm Certifactory.Tests/UnitTest1.cs
```

- [ ] **Step 2: Final commit**

```bash
git add -A
git commit -m "chore: remove xunit template stub"
```

---

## What we deliberately did not do (for the .NET 10 follow-up PR)

- **Did not bump the TFM.** Stayed on net8.0 throughout.
- **Did not use System.Security.Cryptography.MLDsa / SlhDsa / MLKem.** All PQ primitives flow through BouncyCastle. The `IPqSigner` interface is the seam where this swap will happen — `MlDsaSigner.GenerateKeyPair`, `LoadKeyPair`, and `CreateSignatureFactory` are the three methods to rewrite per algorithm.
- **Did not add ML-KEM** (key encapsulation). The current commands all generate certificates and key pairs for signing only. KEM is relevant for TLS 1.3 hybrid handshakes, not cert issuance, and would belong in a separate command if needed.
- **Did not implement the `gpg` PQ path.** GnuPG's experimental Kyber support is not standardized and not interoperable. Reassess once `draft-ietf-openpgp-pqc` lands as an RFC.
- **Did not change the `ssh` command.** OpenSSH's hybrid PQ work is in KEX, not in identity keys; the existing 4096-bit RSA SSH key is fine.

---

## Notes on hybrid X.509 standards drift

The X.509:2019 alt-extension approach used here is one of two competing designs:

1. **Alt-extensions (X.509:2019)** — what this plan implements. Backward-compatible by design (legacy verifiers ignore unknown non-critical extensions).
2. **Composite signatures (`draft-ietf-lamps-pq-composite-sigs`)** — uses a single signature field with a composite OID; both signatures concatenated as the signature value. Not backward-compatible (legacy verifiers don't recognize the composite OID).

If the IETF LAMPS working group's composite-sigs draft progresses faster than expected and becomes the dominant interoperability target, a Phase 9 could add `--algorithm composite-rsa-mldsa` alongside `hybrid`. The two are not mutually exclusive — they target different deployment scenarios.

The Microsoft, Google, and Cloudflare certificate teams have all signaled support for the alt-extension approach as the practical path for the migration window. AWS is a partial outlier with composite-sig experimentation. Our pick — alt-extensions — aligns with the larger camp.
