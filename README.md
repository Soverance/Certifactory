# Certifactory

A dotnet certificate generation command line utility.

You can use this CLI tool to quickly create basic certificate infrastructure for your organization. Create your own private root certificate authority, and sign custom server certificates using your private CA. You can also generate user-specific S/MIME certificates, used for secure email and document signing.

Generated certificates are exported as a password-protected PFX bundle, good for importing the certs into Windows certificate stores.

You can then use this utility to export the PFX bundle into decrypted PEM encoded files, good for installing the certs on Linux operating systems.

All commands that accept an `exportDirectory` parameter will automatically create the directory if it does not exist.

# Algorithm options

The `ca`, `server`, and `smime` commands accept an `--algorithm` flag that selects the signing algorithm for the generated certificate:

| Value | Description | When to use |
|---|---|---|
| `rsa-4096` (default) | Classical RSA-4096 with SHA-256 | Maximum compatibility — every existing client trusts it |
| `ml-dsa-65` | FIPS 204 ML-DSA-65 (post-quantum lattice signatures) | Internal-only deployments where you control all clients and want pure PQC |
| `slh-dsa-256s` | FIPS 205 SLH-DSA-SHA2-256s (hash-based) | Long-lived offline root CAs where signature size doesn't matter and conservative security assumptions are paramount |
| `hybrid` | RSA-4096 primary + ML-DSA-65 alt-signature (X.509:2019 alt-sig extensions) | Production deployments — legacy clients see classical RSA, PQ-aware clients can validate the alt chain |

**Hybrid certificates** use non-critical X.509 extensions (`subjectAltPublicKeyInfo` 2.5.29.72, `altSignatureAlgorithm` 2.5.29.73, `altSignatureValue` 2.5.29.74) to embed a second signature alongside the classical one. Verifiers that don't understand these extensions ignore them and validate the cert as a normal RSA chain. Verifiers that do understand them can additionally validate the post-quantum alt chain.

When issuing a leaf cert (`server` or `smime`), the leaf's algorithm is determined by `--algorithm`. The CA's algorithm is auto-detected from the loaded CA PFX — pass a hybrid CA and the leaf will be signed with hybrid two-pass TBS construction.

# Commands

<details>
<summary><strong>ca</strong> — Generate Root CA Certificate</summary>

```
certifactory ca <certificateName> <certificatePassword> <exportDirectory> [--algorithm <name>]
```

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name for the root CA, i.e. `"encryption.soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX bundle. |
| `exportDirectory` | The directory where the resulting PFX file will be exported. |
| `--algorithm` | (Optional) Signing algorithm: `rsa-4096` (default), `ml-dsa-65`, `slh-dsa-256s`, `hybrid`. See [Algorithm options](#algorithm-options). |

On Windows, install in the **Trusted Root Certification Authority** certificate store.

[Full documentation](docs/ca.md)

</details>

<details>
<summary><strong>server</strong> — Generate Server Certificate</summary>

```
certifactory server <certificateName> <certificatePassword> <serverIP> <rootCA> <rootCAPassword> <exportDirectory> [--algorithm <name>]
```

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name for the server application, i.e. `"soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX bundle. |
| `serverIP` | The IP address of the server where this certificate will be installed. |
| `rootCA` | The absolute path of the root CA PFX that will sign this certificate. |
| `rootCAPassword` | The password used to secure the Root CA PFX file. |
| `exportDirectory` | The directory where the resulting PFX file will be exported. |
| `--algorithm` | (Optional) Signing algorithm for the leaf cert: `rsa-4096` (default), `ml-dsa-65`, `slh-dsa-256s`, `hybrid`. The CA's algorithm is auto-detected from the loaded PFX. See [Algorithm options](#algorithm-options). |

[Full documentation](docs/server.md)

</details>

<details>
<summary><strong>smime</strong> — Generate S/MIME Certificate</summary>

```
certifactory smime <certificateName> <certificatePassword> <userEmail> <rootCA> <rootCAPassword> <exportDirectory> [--algorithm <name>]
```

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name, i.e. `"scott@soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX bundle. |
| `userEmail` | The email address of the user account. |
| `rootCA` | The absolute path of the root CA PFX that will sign this certificate. |
| `rootCAPassword` | The password used to secure the Root CA PFX file. |
| `exportDirectory` | The directory where the resulting PFX file will be exported. |
| `--algorithm` | (Optional) Signing algorithm for the leaf cert: `rsa-4096` (default), `ml-dsa-65`, `slh-dsa-256s`, `hybrid`. The CA's algorithm is auto-detected from the loaded PFX. See [Algorithm options](#algorithm-options). |

On Windows, install in the **Trusted People** and user's **Personal** certificate stores.

[Full documentation](docs/smime.md)

</details>

<details>
<summary><strong>testpfx</strong> — Test PFX Password</summary>

```
certifactory testpfx <certificatePfx> <certificatePassword>
```

| Parameter | Description |
|---|---|
| `certificatePfx` | The absolute path to a password-protected PFX certificate bundle. |
| `certificatePassword` | The password you wish to test against the PFX file. |

Displays certificate details (subject, thumbprint, issuer, validity dates) if the password is correct, or an error message if incorrect.

[Full documentation](docs/testpfx.md)

</details>

<details>
<summary><strong>export</strong> — Export PEM Encoded Files</summary>

```
certifactory export <certificatePfx> <certificatePassword> <exportDirectory>
```

| Parameter | Description |
|---|---|
| `certificatePfx` | The absolute path to a password-protected PFX certificate bundle. |
| `certificatePassword` | The password used to secure the PFX certificate bundle. |
| `exportDirectory` | The directory where the resulting PEM files will be exported. |

Exports `.cer`, `.crt.pem`, and `.key.pem` files for use on Linux systems.

[Full documentation](docs/export.md)

</details>

<details>
<summary><strong>scan</strong> — Inventory Certificates as a CycloneDX 1.6 CBOM</summary>

```
certifactory scan [paths...] [--output <file>] [--pfx-password-file <file>] [--system-stores] [--summary]
```

Walks the given files/directories (and, with `--system-stores`, OS certificate stores) and emits a CycloneDX 1.6 (ECMA-424) Cryptographic Bill of Materials (CBOM) describing every certificate, algorithm, and public key found — each classified by post-quantum readiness. Read-only and fully offline; never prompts for or emits private-key material.

| Parameter | Description |
|---|---|
| `paths...` | (Optional) One or more files or directories to scan. Recognizes `.pem`, `.crt`, `.cer`, `.der`, `.pfx`, `.p12`; directories are walked recursively. |
| `--output` | (Optional) Write the CBOM JSON to this file instead of standard output. |
| `--pfx-password-file` | (Optional) Path to a file holding the password for encrypted PFX/P12 keystores. Without it, encrypted keystores are skipped with a warning (never a prompt). |
| `--system-stores` | (Optional) Also scan OS certificate stores — the Windows certificate stores (CurrentUser + LocalMachine: Personal, Trusted Root, Intermediate, Trusted People) or, on non-Windows systems, the well-known PEM directories. |
| `--summary` | (Optional) Print a post-quantum readiness summary table to stderr (stdout stays pure CBOM JSON). |

The emitted CBOM validates against the CycloneDX 1.6 schema and is consumable by any CycloneDX 1.6-aware tool.

[Full documentation](docs/scan.md)

</details>

<details>
<summary><strong>tls-scan</strong> — Probe TLS Endpoints and Emit a CycloneDX 1.6 CBOM</summary>

```
certifactory tls-scan [targets...] [--targets-file <file>] [--output <file>] [--summary] [--timeout <seconds>] [--concurrency <n>]
```

Probes TLS endpoints over the network to inventory negotiated protocol parameters, certificate chains, and key-exchange groups. Emits a CycloneDX 1.6 (ECMA-424) Cryptographic Bill of Materials (CBOM) describing each asset and classifying it by post-quantum readiness. **Authorization required:** You must be authorized to scan the endpoints you specify. The tool makes outbound connections only to the named targets and never modifies the remote server.

| Parameter | Description |
|---|---|
| `targets...` | (Optional) TLS endpoints as `host:port` pairs (e.g., `example.com:443`, `api.example.com:8443`). Zero or more may be provided; if none (and no `--targets-file`), the command emits an empty CBOM rather than erroring. |
| `--targets-file` | (Optional) Path to a file with one `host:port` target per line. Empty lines and lines starting with `#` (comments) are ignored. |
| `--output` | (Optional) Write the CBOM JSON to this file instead of standard output. |
| `--summary` | (Optional) Print a post-quantum readiness summary table to stderr (stdout stays pure CBOM JSON). |
| `--timeout` | (Optional) Per-target handshake timeout in seconds (default 10). |
| `--concurrency` | (Optional) Maximum concurrent handshakes (default 8). |

[Full documentation](docs/tls-scan.md)

</details>

<details>
<summary><strong>risk</strong> — Score a CBOM for Post-Quantum Risk</summary>

```
certifactory risk [--input <cbom.json>] [--format table|json] [--report <path.md>] [--top <N>] [--quantum-year <YYYY>] [--data-shelf-life <years>] [--migration-time <years>] [--fail-over <score>]
```

Consumes a CycloneDX 1.6 CBOM (from `scan`, `tls-scan`, or any other CycloneDX-1.6-conformant source) and produces a prioritized post-quantum risk assessment: a 0–100 score per certificate/TLS endpoint that rolls up into an A–F inventory grade. Reads stdin by default, so `certifactory scan ./certs | certifactory risk` works out of the box.

| Parameter | Description |
|---|---|
| `--input` | (Optional) Read the CBOM from this file instead of stdin. |
| `--format` | (Optional) Console output: `table` (default) or `json`. |
| `--report` | (Optional) Also write a shareable Markdown risk report to this path. |
| `--top` | (Optional) Limit the prioritized asset list to the N highest-risk assets. Default: 20. |
| `--quantum-year`, `--data-shelf-life`, `--migration-time` | (Optional) Mosca time-horizon override for the validity factor. See [Post-quantum risk scoring](#post-quantum-risk-scoring). |
| `--fail-over` | (Optional) CI gate: exit code 2 if the inventory score exceeds this value. |

Exit codes: `0` success, `1` CBOM could not be parsed, `2` `--fail-over` threshold exceeded.

See [Post-quantum risk scoring](#post-quantum-risk-scoring) below for the complete scoring ruleset.

[Full documentation](docs/risk.md)

</details>

<details>
<summary><strong>ssh</strong> — Generate SSH Keypair</summary>

```
certifactory ssh <keyName> <comment> <exportDirectory>
```

| Parameter | Description |
|---|---|
| `keyName` | The name for the output key files (`keyName` and `keyName.pub`). |
| `comment` | A comment embedded in the public key, typically `user@hostname`. |
| `exportDirectory` | The directory where the resulting key files will be exported. |

Generates a 4096-bit RSA SSH keypair in PKCS#1 PEM (private) and OpenSSH (public) formats. On Linux, remember to `chmod 600` the private key.

[Full documentation](docs/ssh.md)

</details>

<details>
<summary><strong>gpg</strong> — Generate GPG Keypair</summary>

```
certifactory gpg <keyName> <userName> <email> <passphrase> <exportDirectory>
```

| Parameter | Description |
|---|---|
| `keyName` | The name for the output key files (`keyName.gpg.pub` and `keyName.gpg.sec`). |
| `userName` | The real name for the GPG User ID. Should match your GitHub display name. |
| `email` | The email for the GPG User ID. Must match your GitHub account email. |
| `passphrase` | The passphrase used to protect the private key. |
| `exportDirectory` | The directory where the resulting key files will be exported. |

Generates a 4096-bit RSA GPG keypair for GitHub commit signing. If `gpg` is found in PATH, Certifactory will automatically import the key, configure gpg-agent for passphrase caching, and set up git for commit signing.

[Full documentation](docs/gpg.md)

</details>

# Post-quantum risk scoring

The `risk` command (see above; full reference in [docs/risk.md](docs/risk.md)) turns a CBOM into a prioritized post-quantum risk assessment using a documented, zero-config heuristic. This section is the **complete ruleset** — every number the scorer uses — so a score is defensible and citable.

## Scoring model

**Per-asset score = `100 × readinessFactor × exposure`**, clamped to `0–100`. An "asset" is a certificate or a TLS endpoint (protocol) component in the CBOM.

### `readinessFactor` — the gate

Post-quantum readiness gates the score: no vulnerability, no risk.

| Readiness | Factor |
|---|---|
| Vulnerable (RSA / ECDSA / DH) | 1.00 |
| Unknown / unclassified | 0.85 |
| Hybrid (transitional) | 0.35 |
| Quantum-safe (ML-DSA / SLH-DSA) | 0.00 |

A quantum-safe asset always scores **0** — the gate zeroes out anything already migrated, no matter how exposed it would otherwise be. For a **certificate** (which references both a signature algorithm and a subject-key algorithm), readiness is the **worst** (most vulnerable) of the two — pessimistic, matching the existing `scan`/`tls-scan` classification.

### `exposure` — the amplifier

`exposure` is the weighted average of four factors, each in `[0, 1]`, answering "how urgent is it that this particular asset is vulnerable":

`exposure = 0.40 × usage + 0.25 × role + 0.20 × validity + 0.15 × keyStrength`

| Factor | Weight | Scoring |
|---|---|---|
| **HNDL usage** | 0.40 | key-establishment / both / unknown = **1.0** · signature-only = **0.3** |
| **Asset role** (blast radius) | 0.25 | root CA = **1.0** · intermediate CA = **0.7** · TLS endpoint = **0.5** · leaf / unknown = **0.3** |
| **Validity window** | 0.20 | >10 yr remaining = **1.0** · 5–10 yr = **0.7** · 1–5 yr = **0.4** · <1 yr = **0.15** |
| **Key strength** | 0.15 | <2048-bit = **1.0** · 2048–<4096-bit = **0.5** · ≥4096-bit = **0.2** · unknown = **0.5** |

**Why HNDL usage is weighted highest:** encryption / key-exchange keys are the ones an adversary can *harvest today and decrypt after Q-day* (harvest-now-decrypt-later) — genuinely urgent regardless of when Q-day actually arrives. Signatures only become forgeable *after* Q-day, so a signature-only certificate that expires before then is far less pressing. For a certificate, usage is read from the **subject key's** KeyUsage extension (the key that protects data). A TLS endpoint has no certificate expiry of its own — it is always treated as key-establishment usage, its role is always `tls-endpoint`, and its readiness comes from the negotiated key-exchange group's classification rather than a certificate's signature/key algorithms.

### Grade bands

Applied to both per-asset scores and the inventory roll-up:

| Score | Grade | Label |
|---|---|---|
| ≤ 20 | A | Low |
| ≤ 40 | B | Guarded |
| ≤ 60 | C | Elevated |
| ≤ 80 | D | High |
| > 80 | F | Critical |

### Inventory roll-up

Inventory score = the **mean** of per-asset scores; the grade is derived from the bands above. Reports always surface per-band counts and the full worst-first ranking, so a small number of Critical assets is never hidden by averaging.

### Mosca time-horizon override

By default, the validity factor uses each asset's raw remaining certificate lifetime (a TLS endpoint uses the maximum, `1.0`, absent an override — a live session has no expiry date of its own). Supplying **both** `--quantum-year <YYYY>` and `--data-shelf-life <years>` (plus optional `--migration-time <years>`, default **1**) *reinterprets* the validity factor using Mosca's inequality instead:

- `yearsToQ` = `quantum-year` − the current (fractional) year.
- `horizon` = `data-shelf-life` + `migration-time`.
- If Q-day has already passed, or `horizon ≥ yearsToQ` (the protected data would still need to be secret when the CRQC arrives), the validity factor **saturates to 1.0**.
- Otherwise the factor scales proportionally, `horizon / yearsToQ`, clamped to **[0.15, 1.0]**.

All other factors (usage, role, key strength) are unaffected by the override.

### Graceful degradation on un-enriched CBOMs

`risk` degrades conservatively when scoring a CBOM that lacks Certifactory's enrichment properties (`certifactory:certificate:role`, `certifactory:key:usage`) — an older Certifactory CBOM, or a third-party one:

- Missing usage → assumed worst case, **usage factor 1.0** (as if key-establishment).
- Missing role → treated as **leaf** (role factor 0.3).
- Missing/unparseable validity date → **mid-exposure, 0.4** (only relevant absent a Mosca override).

Whenever no component in the CBOM carries the `certifactory:certificate:role` property, both the console output and the Markdown report print a one-line note — *"input CBOM lacked certifactory enrichment (cert role / key usage); scores use conservative worst-case defaults"* — so a degraded score is never mistaken for a fully-informed one.

### Worked examples

- **Vulnerable root-CA key-establishment cert** (RSA-4096, 15 yr remaining): `exposure = 0.40·1.0 + 0.25·1.0 + 0.20·1.0 + 0.15·0.2 = 0.88` → `100 × 1.00 × 0.88 = 88` → **F, Critical**.
- **Vulnerable leaf signature-only cert** (RSA-4096, expires in 6 mo): `exposure = 0.40·0.3 + 0.25·0.3 + 0.20·0.15 + 0.15·0.2 = 0.255` → `100 × 1.00 × 0.255 = 25.5` → **B, Guarded**.
- **Any quantum-safe asset**: **0**, always (the gate).

Full command reference (flags, exit codes, examples): [docs/risk.md](docs/risk.md).
