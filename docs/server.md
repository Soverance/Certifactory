# Generate Server Certificate

## Usage

```
certifactory server <certificateName> <certificatePassword> <serverIP> <rootCA> <rootCAPassword> <exportDirectory> [--algorithm <name>]
```

## Parameters

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name for the server application, i.e. `"soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX certificate bundle. |
| `serverIP` | The IP address of the server where this certificate will be installed. |
| `rootCA` | The absolute path of the root certificate authority PFX that will sign this certificate. |
| `rootCAPassword` | The password used to secure the Root CA PFX file. |
| `exportDirectory` | The file path to a directory where the resulting PFX file will be exported. The directory will be created if it does not exist. |
| `--algorithm` | (Optional) Signing algorithm for the leaf cert: `rsa-4096` (default), `ml-dsa-65`, `slh-dsa-256s`, or `hybrid`. The CA's algorithm is auto-detected from the loaded PFX. See [Algorithm selection](#algorithm-selection) below. |

## Details

Creates a server certificate signed by the specified root CA with a 396-day validity period (within the iOS trust limit). The certificate includes both Server Authentication and Client Authentication extended key usages, and adds the certificate name as a DNS SAN and the server IP as an IP SAN.

The certificate is exported as a password-protected PFX bundle.

## Algorithm selection

Pass `--algorithm` to choose the leaf's signing algorithm. The CA's algorithm is auto-detected from the loaded PFX — pass a hybrid CA and the leaf will be signed via the X.509:2019 two-pass alt-sig construction. See the README for the full comparison table.

Example — issue a hybrid leaf from a hybrid CA:

```
certifactory server srv.example.com SrvPass "" /etc/certs/my-org-root.pfx MyPass /etc/certs --algorithm hybrid
```

Example — issue an ML-DSA-only leaf from an ML-DSA CA:

```
certifactory server srv.example.com SrvPass "" /etc/certs/ml-dsa-root.pfx Pass /etc/certs --algorithm ml-dsa-65
```

The leaf's algorithm should generally match the CA's. Mixing — e.g. an RSA leaf signed by a hybrid CA — is supported (the CA's primary classical key signs the leaf), but the leaf will only have a classical signature, defeating the purpose of the hybrid CA. For consistent post-quantum coverage, use the same algorithm at every level of the chain.

Issuing a hybrid leaf from a non-hybrid CA fails — the CA needs both a classical and a PQ private key to produce the two-pass alt-signature.
