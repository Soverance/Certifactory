# Certifactory
A dotnet certificate generation command line utility.

You can use this CLI tool to quickly create basic certificate infrastructure for your organization.  Create your own private root certificate authority, and sign custom server certificates using your private CA.

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


## Generate Server Certificate
>Usage:\
>`certifactory server <certificateName> <certificatePassword> <serverIP> <exportDirectory> <rootCA>`
>
>Required Parameters:	
>	- `certificateName`			The certificate name for the root certificate authority, i.e. "encryption.soverance.com".
>	- `certificatePassword`		The password used to secure the resulting PFX certificate bundle.
>	- `serverIP`				The IP address of the server where this certificate will be installed.
>	- `exportDirectory`			The absolute file path to a directory where you intend the resulting PFX file to be exported.
>	- `rootCA`					The absolute path of the root certificate authority that will sign this certificate.

## Export PEM Encoded Files
>Usage:\
>`certifactory export <certificatePfx> <certificatePassword> <exportDirectory>`
>
>Required Parameters:
>	- `certificatePfx`			The absolute path to a password-protected PFX certificate bundle.
>	- `certificatePassword`		The password used to secure the PFX certificate bundle.
>	- `exportDirectory`			The absolute file path to a directory where you intend the resulting PEM files to be exported.
