# Generate SSH Keypair

## Usage

```
certifactory ssh <keyName> <comment> <exportDirectory>
```

## Parameters

| Parameter | Description |
|---|---|
| `keyName` | The name used for the output key files. The private key will be saved as `keyName` (no extension) and the public key as `keyName.pub`. |
| `comment` | A comment embedded in the public key, typically in `user@hostname` format. |
| `exportDirectory` | The file path to a directory where the resulting key files will be exported. The directory will be created if it does not exist. |

## Details

Generates a 4096-bit RSA SSH keypair. The private key is exported in PKCS#1 PEM format and the public key in OpenSSH format (`ssh-rsa`), compatible with all major Linux distributions and services like GitHub.

## Post-Generation

On Linux, set permissions on the private key:

```
chmod 600 <keyName>
```
