# Generate S/MIME Certificate

## Usage

```
certifactory smime <certificateName> <certificatePassword> <userEmail> <rootCA> <rootCAPassword> <exportDirectory> [--algorithm <name>]
```

## Parameters

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name. For ease of use, you should specify an email address, i.e. `"scott@soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX certificate bundle. |
| `userEmail` | The email address of the user account for which you wish to generate the certificate. |
| `rootCA` | The absolute path of the root certificate authority PFX that will sign this certificate. |
| `rootCAPassword` | The password used to secure the Root CA PFX file. |
| `exportDirectory` | The file path to a directory where the resulting PFX file will be exported. The directory will be created if it does not exist. |
| `--algorithm` | (Optional) Signing algorithm for the leaf cert: `rsa-4096` (default), `ml-dsa-65`, `slh-dsa-256s`, or `hybrid`. The CA's algorithm is auto-detected from the loaded PFX. See [Algorithm selection](#algorithm-selection) below. |

## Details

Creates an S/MIME certificate signed by the specified root CA with a 10-year validity period. The certificate includes Document Signing and Secure Email extended key usages, and embeds the email address in the SubjectAlternativeName extension as an `rfc822Name`.

The certificate is exported as a password-protected PFX bundle.

## Algorithm selection

Pass `--algorithm` to choose the leaf's signing algorithm. The CA's algorithm is auto-detected from the loaded PFX. See the README for the full comparison table.

Example — issue a hybrid S/MIME cert from a hybrid CA:

```
certifactory smime alice@example.com Pass alice@example.com /etc/certs/my-org-root.pfx MyPass /etc/certs --algorithm hybrid
```

The leaf's algorithm should generally match the CA's. Mixing — e.g. an RSA leaf signed by a hybrid CA — is supported (the CA's primary classical key signs the leaf), but the leaf will only have a classical signature, defeating the purpose of the hybrid CA. For consistent post-quantum coverage, use the same algorithm at every level of the chain.

## Post-Generation

On Windows, these certificates should be installed in the **Trusted People** certificate store, as well as in the user's **Personal** certificate store.

> **Note:** S/MIME configuration is complicated, and you would ideally use a public CA (such as DigiCert) to ensure maximum compatibility with all recipients. Self-signed S/MIME certificates work best when sending email within your organization, where recipients have the private CA certificate installed as a trusted root CA.
