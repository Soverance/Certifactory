# Generate Root CA Certificate

## Usage

```
certifactory ca <certificateName> <certificatePassword> <exportDirectory> [--algorithm <name>]
```

## Parameters

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name for the root certificate authority, i.e. `"encryption.soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX certificate bundle. |
| `exportDirectory` | The file path to a directory where the resulting PFX file will be exported. The directory will be created if it does not exist. |
| `--algorithm` | (Optional) Signing algorithm: `rsa-4096` (default), `ml-dsa-65`, `slh-dsa-256s`, or `hybrid`. See [Algorithm selection](#algorithm-selection) below. |

## Details

Creates a self-signed root certificate authority with a 20-year validity period. The root CA can then be used to sign server certificates and S/MIME certificates using the `server` and `smime` commands.

The certificate is exported as a password-protected PFX bundle. For `hybrid` certs, the PFX contains BOTH the classical RSA private key and the post-quantum ML-DSA private key under separate aliases — both are needed when the CA is later reloaded to issue more leaves.

## Algorithm selection

Pass `--algorithm` to choose the signing algorithm. See the README for the full comparison table.

Example — generate a hybrid root CA (RSA-4096 primary + ML-DSA-65 alt-signature):

```
certifactory ca my-org-root MyPass /etc/certs --algorithm hybrid
```

Example — generate an SLH-DSA root for an air-gapped offline signing facility (conservative hash-based PQC):

```
certifactory ca offline-root MyPass /secure/certs --algorithm slh-dsa-256s
```

When generating leaf certs (`server` or `smime`), the leaf's algorithm should generally match the CA's. Mixing — e.g. an RSA leaf signed by a hybrid CA — is supported (the CA's primary classical key signs the leaf), but the leaf will only have a classical signature, defeating the purpose of the hybrid CA. For consistent post-quantum coverage, use the same algorithm at every level of the chain.

## Post-Generation

On Windows, these certificates should be installed in the **Trusted Root Certification Authority** certificate store.
