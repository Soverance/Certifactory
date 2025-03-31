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
>`certifactory server <certificateName> <certificatePassword> <serverIP> <rootCA> <rootCAPassword> <exportDirectory>`
>
>Required Parameters:	
>	- `certificateName`			The certificate name for the root certificate authority, i.e. "encryption.soverance.com".
>	- `certificatePassword`		The password used to secure the resulting PFX certificate bundle.
>	- `serverIP`				The IP address of the server where this certificate will be installed.
>	- `rootCA`					The absolute path of the root certificate authority that will sign this certificate.
>	- `rootCAPassword`			The password used to secure the Root CA PFX file.
>	- `exportDirectory`			The absolute file path to a directory where you intend the resulting PFX file to be exported.


## Generate S/MIME Certificate
>Usage:\
>`certifactory smime <certificateName> <certificatePassword> <userEmail> <exportDirectory> <rootCA>`
>
>Required Parameters:	
>	- `certificateName`			The certificate name for the root certificate authority, i.e. "encryption.soverance.com".
>	- `certificatePassword`		The password used to secure the resulting PFX certificate bundle.
>	- `userEmail`				The email address of the of the user account for which you wish to generate the certificate.
>	- `rootCA`					The absolute path of the root certificate authority that will sign this certificate.
>	- `rootCAPassword`			The password used to secure the Root CA PFX file.
>	- `exportDirectory`			The absolute file path to a directory where you intend the resulting PFX file to be exported.
	

## Export PEM Encoded Files
>Usage:\
>`certifactory export <certificatePfx> <certificatePassword> <exportDirectory>`
>
>Required Parameters:
>	- `certificatePfx`			The absolute path to a password-protected PFX certificate bundle.
>	- `certificatePassword`		The password used to secure the PFX certificate bundle.
>	- `exportDirectory`			The absolute file path to a directory where you intend the resulting PEM files to be exported.
