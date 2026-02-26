# Generate GPG Keypair

## Usage

```
certifactory gpg <keyName> <userName> <email> <passphrase> <exportDirectory>
```

## Parameters

| Parameter | Description |
|---|---|
| `keyName` | The name used for the output key files. The public key will be saved as `keyName.gpg.pub` and the secret key as `keyName.gpg.sec`. |
| `userName` | The real name for the GPG User ID (e.g. `"Scott McCutchen"`). This should match your GitHub display name. |
| `email` | The email address for the GPG User ID. This must match the email address associated with your GitHub account. |
| `passphrase` | The passphrase used to protect the private key. |
| `exportDirectory` | The file path to a directory where the resulting key files will be exported. The directory will be created if it does not exist. |

## Details

Generates a 4096-bit RSA GPG keypair suitable for GitHub commit signing. The keypair includes a master key (sign + certify) and an encryption subkey. Keys are exported in ASCII-armored OpenPGP format.

## Automatic Configuration (when `gpg` is in PATH)

If `gpg` is found on the system, Certifactory will automatically:

1. **Configure gpg-agent** for loopback pinentry and long-lived passphrase caching by updating `gpg-agent.conf` with:
   ```
   default-cache-ttl 34560000
   max-cache-ttl 34560000
   allow-preset-passphrase
   allow-loopback-pinentry
   ```
2. **Import the secret key** into your GPG keyring via `gpg --import`, using loopback pinentry mode to avoid the Pinentry GUI passphrase prompt
3. **Set ownertrust to ultimate** so GPG does not display trust warnings when signing
4. **Pre-seed the passphrase** into `gpg-agent` using `gpg-preset-passphrase`, so you are never prompted for the passphrase during commit signing
5. **Configure git globally** for commit signing:
   ```
   git config --global user.signingkey <KEY_ID>
   git config --global commit.gpgsign true
   git config --global gpg.program <path-to-gpg>
   ```
   Setting `gpg.program` ensures git uses the same `gpg.exe` that holds the imported key, avoiding conflicts with the GPG binary bundled inside Git for Windows.

After automatic configuration, commit signing should work immediately with no further setup.

## Manual Configuration (when `gpg` is not in PATH)

If `gpg` is not found, you can import and configure manually:

```
gpg --import <keyName>.gpg.sec
git config --global user.signingkey <KEY_ID>
git config --global commit.gpgsign true
git config --global gpg.program "C:\path\to\gpg.exe"
```

To avoid being prompted for the passphrase on every commit, configure `gpg-agent.conf` (located at `%APPDATA%\gnupg\gpg-agent.conf` on Windows, or `~/.gnupg/gpg-agent.conf` on Linux/macOS) with:

```
default-cache-ttl 34560000
max-cache-ttl 34560000
```

Then restart the agent with `gpg-connect-agent reloadagent /bye`.

## Adding the Key to GitHub

To add the public key to GitHub, copy the contents of the `.gpg.pub` file and paste it into **GitHub > Settings > SSH and GPG keys > New GPG key**.
