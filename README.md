# Certifactory

A dotnet certificate generation command line utility.

You can use this CLI tool to quickly create basic certificate infrastructure for your organization. Create your own private root certificate authority, and sign custom server certificates using your private CA. You can also generate user-specific S/MIME certificates, used for secure email and document signing.

Generated certificates are exported as a password-protected PFX bundle, good for importing the certs into Windows certificate stores.

You can then use this utility to export the PFX bundle into decrypted PEM encoded files, good for installing the certs on Linux operating systems.

All commands that accept an `exportDirectory` parameter will automatically create the directory if it does not exist.

# Commands

<details>
<summary><strong>ca</strong> — Generate Root CA Certificate</summary>

```
certifactory ca <certificateName> <certificatePassword> <exportDirectory>
```

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name for the root CA, i.e. `"encryption.soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX bundle. |
| `exportDirectory` | The directory where the resulting PFX file will be exported. |

On Windows, install in the **Trusted Root Certification Authority** certificate store.

[Full documentation](docs/ca.md)

</details>

<details>
<summary><strong>server</strong> — Generate Server Certificate</summary>

```
certifactory server <certificateName> <certificatePassword> <serverIP> <rootCA> <rootCAPassword> <exportDirectory>
```

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name for the server application, i.e. `"soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX bundle. |
| `serverIP` | The IP address of the server where this certificate will be installed. |
| `rootCA` | The absolute path of the root CA PFX that will sign this certificate. |
| `rootCAPassword` | The password used to secure the Root CA PFX file. |
| `exportDirectory` | The directory where the resulting PFX file will be exported. |

[Full documentation](docs/server.md)

</details>

<details>
<summary><strong>smime</strong> — Generate S/MIME Certificate</summary>

```
certifactory smime <certificateName> <certificatePassword> <userEmail> <rootCA> <rootCAPassword> <exportDirectory>
```

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name, i.e. `"scott@soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX bundle. |
| `userEmail` | The email address of the user account. |
| `rootCA` | The absolute path of the root CA PFX that will sign this certificate. |
| `rootCAPassword` | The password used to secure the Root CA PFX file. |
| `exportDirectory` | The directory where the resulting PFX file will be exported. |

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
