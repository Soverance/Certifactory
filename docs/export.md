# Export PEM Encoded Files

## Usage

```
certifactory export <certificatePfx> <certificatePassword> <exportDirectory>
```

## Parameters

| Parameter | Description |
|---|---|
| `certificatePfx` | The absolute path to a password-protected PFX certificate bundle. |
| `certificatePassword` | The password used to secure the PFX certificate bundle. |
| `exportDirectory` | The file path to a directory where the resulting PEM files will be exported. The directory will be created if it does not exist. |

## Details

Extracts and exports the public certificate and private key from a PFX bundle into PEM-encoded files suitable for use on Linux systems. Three files are generated:

- `<name>.cer` — Public certificate in PEM format
- `<name>.crt.pem` — Public certificate in PEM format
- `<name>.key.pem` — RSA private key in PEM format (unencrypted)

Where `<name>` is the filename of the input PFX file (without extension).
