# Certifactory
Certificate generation command line tool.

# Commands
## Generate Root CA Certificate
>>>

Usage: `certifactory ca <certificateName> <certificatePassword> <exportDirectory>`

Required Parameters:

	* `certificateName`			The certificate name for the root certificate authority, i.e. "encryption.soverance.com".
	* `certificatePassword`		The password used to secure the resulting PFX certificate bundle.
	* `exportDirectory`			The absolute file path to a directory where you intend the resulting PFX file to be exported.
>>>

## Generate Server Certificate
>>>

Usage: `certifactory server <certificateName> <certificatePassword> <serverIP> <exportDirectory> <rootCA>`

Required Parameters:
	
	* `certificateName`			The certificate name for the root certificate authority, i.e. "encryption.soverance.com".
	* `certificatePassword`		The password used to secure the resulting PFX certificate bundle.
	* `serverIP`				The IP address of the server where this certificate will be installed.
	* `exportDirectory`			The absolute file path to a directory where you intend the resulting PFX file to be exported.
	* `rootCA`					The absolute path of the root certificate authority that will sign this certificate.
>>>

## Export PEM Encoded Files
>>>

Usage: `certifactory export <certificatePfx> <certificatePassword> <exportDirectory>`

Required Parameters:

	* `certificatePfx`			The absolute path to a password-protected PFX certificate bundle.
	* `certificatePassword`		The password used to secure the PFX certificate bundle.
	* `exportDirectory`			The absolute file path to a directory where you intend the resulting PEM files to be exported.
>>>