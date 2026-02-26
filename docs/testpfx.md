# Test PFX Password

## Usage

```
certifactory testpfx <certificatePfx> <certificatePassword>
```

## Parameters

| Parameter | Description |
|---|---|
| `certificatePfx` | The absolute path to a password-protected PFX certificate bundle. |
| `certificatePassword` | The password you wish to test against the PFX file. |

## Details

Attempts to open the specified PFX file with the given password.

If the password is correct, certificate details will be displayed:
- Subject
- Thumbprint
- Issuer
- Not Before (validity start date)
- Not After (validity end date)

If the password is incorrect or the PFX file is invalid, an error message will be displayed instead.
