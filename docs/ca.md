# Generate Root CA Certificate

## Usage

```
certifactory ca <certificateName> <certificatePassword> <exportDirectory>
```

## Parameters

| Parameter | Description |
|---|---|
| `certificateName` | The certificate name for the root certificate authority, i.e. `"encryption.soverance.com"`. |
| `certificatePassword` | The password used to secure the resulting PFX certificate bundle. |
| `exportDirectory` | The file path to a directory where the resulting PFX file will be exported. The directory will be created if it does not exist. |

## Details

Creates a self-signed root certificate authority with a 20-year validity period. The root CA can then be used to sign server certificates and S/MIME certificates using the `server` and `smime` commands.

The certificate is exported as a password-protected PFX bundle.

## Post-Generation

On Windows, these certificates should be installed in the **Trusted Root Certification Authority** certificate store.
