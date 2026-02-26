# Generate Server Certificate

## Usage

```
certifactory server <certificateName> <certificatePassword> <serverIP> <rootCA> <rootCAPassword> <exportDirectory>
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

## Details

Creates a server certificate signed by the specified root CA with a 396-day validity period (within the iOS trust limit). The certificate includes both Server Authentication and Client Authentication extended key usages, and adds the certificate name as a DNS SAN and the server IP as an IP SAN.

The certificate is exported as a password-protected PFX bundle.
