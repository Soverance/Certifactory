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
