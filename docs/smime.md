# Generate S/MIME Certificate

## Usage

```
certifactory smime <certificateName> <certificatePassword> <userEmail> <rootCA> <rootCAPassword> <exportDirectory>
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

## Details

Creates an S/MIME certificate signed by the specified root CA with a 10-year validity period. The certificate includes Document Signing and Secure Email extended key usages, and adds the email address as both an email SAN and a UPN SAN.

The certificate is exported as a password-protected PFX bundle.

## Post-Generation

On Windows, these certificates should be installed in the **Trusted People** certificate store, as well as in the user's **Personal** certificate store.

> **Note:** S/MIME configuration is complicated, and you would ideally use a public CA (such as DigiCert) to ensure maximum compatibility with all recipients. Self-signed S/MIME certificates work best when sending email within your organization, where recipients have the private CA certificate installed as a trusted root CA.
