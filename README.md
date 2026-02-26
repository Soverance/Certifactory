# Certifactory
A dotnet certificate generation command line utility.

You can use this CLI tool to quickly create basic certificate infrastructure for your organization.  Create your own private root certificate authority, and sign custom server certificates using your private CA. You can also generate user-specific S/MIME certificates, used for secure email and document signing.

Generated certificates are exported as a password-protected PFX bundle, good for importing the certs into Windows certificate stores.

You can then use this utility to export the PFX bundle into decrypted PEM encoded files, good for installing the certs on Linux operating systems.

# Commands
## Generate Root CA Certificate
>Usage:\
>`certifactory ca <certificateName> <certificatePassword> <exportDirectory>`
>
>Required Parameters:
>	* `certificateName`			The certificate name for the root certificate authority, i.e. "encryption.soverance.com".
>	* `certificatePassword`		The password used to secure the resulting PFX certificate bundle.
>	* `exportDirectory`			The absolute file path to a directory where you intend the resulting PFX file to be exported.
	
On Windows, these certificates should be installed in the "Trusted Root Certification Authority" certificate store.	


## Generate Server Certificate
>Usage:\
>`certifactory server <certificateName> <certificatePassword> <serverIP> <rootCA> <rootCAPassword> <exportDirectory>`
>
>Required Parameters:	
>	- `certificateName`			The certificate name for the server application, i.e. "soverance.com".
>	- `certificatePassword`		The password used to secure the resulting PFX certificate bundle.
>	- `serverIP`				The IP address of the server where this certificate will be installed.
>	- `rootCA`					The absolute path of the root certificate authority that will sign this certificate.
>	- `rootCAPassword`			The password used to secure the Root CA PFX file.
>	- `exportDirectory`			The absolute file path to a directory where you intend the resulting PFX file to be exported.
	

## Generate S/MIME Certificate
>Usage:\
>`certifactory smime <certificateName> <certificatePassword> <userEmail> <exportDirectory> <rootCA> <rootCAPassword> <exportDirectory>`
>
>Required Parameters:	
>	- `certificateName`			The certificate name. For ease of use, you should specify an email address, i.e. "scott@soverance.com".
>	- `certificatePassword`		The password used to secure the resulting PFX certificate bundle.
>	- `userEmail`				The email address of the of the user account for which you wish to generate the certificate.
>	- `rootCA`					The absolute path of the root certificate authority that will sign this certificate.
>	- `rootCAPassword`			The password used to secure the Root CA PFX file.
>	- `exportDirectory`			The absolute file path to a directory where you intend the resulting PFX file to be exported.

On Windows, these certificates should be installed in the "Trusted People" certificate store, as well as in the user's "Personal" certificate store.		

## Test PFX Password
>Usage:\
>`certifactory testpfx <certificatePfx> <certificatePassword>`
>
>Required Parameters:
>	- `certificatePfx`			The absolute path to a password-protected PFX certificate bundle.
>	- `certificatePassword`		The password you wish to test against the PFX file.

If the password is correct, certificate details such as the subject, thumbprint, issuer, and validity dates will be displayed. If the password is incorrect or the PFX file is invalid, an error message will be displayed instead.

## Export PEM Encoded Files
>Usage:\
>`certifactory export <certificatePfx> <certificatePassword> <exportDirectory>`
>
>Required Parameters:
>	- `certificatePfx`			The absolute path to a password-protected PFX certificate bundle.
>	- `certificatePassword`		The password used to secure the PFX certificate bundle.
>	- `exportDirectory`			The absolute file path to a directory where you intend the resulting PEM files to be exported.

## Generate SSH Keypair
>Usage:\
>`certifactory ssh <keyName> <comment> <exportDirectory>`
>
>Required Parameters:
>	- `keyName`				The name used for the output key files. The private key will be saved as `keyName` (no extension) and the public key as `keyName.pub`.
>	- `comment`				A comment embedded in the public key, typically in `user@hostname` format.
>	- `exportDirectory`		The absolute file path to a directory where you intend the resulting key files to be exported.

Generates a 4096-bit RSA SSH keypair. The private key is exported in PKCS#1 PEM format and the public key in OpenSSH format (`ssh-rsa`), compatible with all major Linux distributions and services like GitHub. On Linux, remember to set permissions on the private key with `chmod 600`.

## Generate GPG Keypair
>Usage:\
>`certifactory gpg <keyName> <userName> <email> <passphrase> <exportDirectory>`
>
>Required Parameters:
>	- `keyName`				The name used for the output key files. The public key will be saved as `keyName.gpg.pub` and the secret key as `keyName.gpg.sec`.
>	- `userName`			The real name for the GPG User ID (e.g. `"Scott McCutchen"`). This should match your GitHub display name.
>	- `email`				The email address for the GPG User ID. This must match the email address associated with your GitHub account.
>	- `passphrase`			The passphrase used to protect the private key.
>	- `exportDirectory`		The absolute file path to a directory where you intend the resulting key files to be exported.

Generates a 4096-bit RSA GPG keypair suitable for GitHub commit signing. The keypair includes a master key (sign + certify) and an encryption subkey. Keys are exported in ASCII-armored OpenPGP format.

### Automatic Configuration (when `gpg` is in PATH)

If `gpg` is found on the system, Certifactory will automatically:

1. **Import the secret key** into your GPG keyring via `gpg --import`
2. **Set ownertrust to ultimate** so GPG does not display trust warnings when signing
3. **Configure gpg-agent** for long-lived passphrase caching by updating `gpg-agent.conf` with:
   ```
   default-cache-ttl 34560000
   max-cache-ttl 34560000
   allow-preset-passphrase
   ```
4. **Pre-seed the passphrase** into `gpg-agent` using `gpg-preset-passphrase`, so you are never prompted for the passphrase during commit signing
5. **Configure git globally** for commit signing:
   ```
   git config --global user.signingkey <KEY_ID>
   git config --global commit.gpgsign true
   git config --global gpg.program <path-to-gpg>
   ```
   Setting `gpg.program` ensures git uses the same `gpg.exe` that holds the imported key, avoiding conflicts with the GPG binary bundled inside Git for Windows.

After automatic configuration, commit signing should work immediately with no further setup.

### Manual Configuration (when `gpg` is not in PATH)

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

### Adding the Key to GitHub

To add the public key to GitHub, copy the contents of the `.gpg.pub` file and paste it into **GitHub > Settings > SSH and GPG keys > New GPG key**.