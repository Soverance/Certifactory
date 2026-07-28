# scan — Inventory Certificates as a CycloneDX 1.6 CBOM

## Purpose

The `scan` command walks local files, directories, and (optionally) OS certificate stores to inventory all certificates, public keys, and cryptographic algorithms found. It emits a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) describing each asset and classifying it by post-quantum readiness — helping you prepare for the transition to post-quantum cryptography.

The scan is **fully offline**, **read-only**, and **never requires passwords** for unencrypted formats. Encrypted PFX/P12 keystores can optionally be decrypted with `--pfx-password-file`, but private-key material is never emitted to the CBOM.

## Command Syntax

```
certifactory scan [paths...] [--output <file>] [--pfx-password-file <file>] [--system-stores] [--summary]
```

## Arguments and Options

### Positional Arguments

| Argument | Description |
|----------|-------------|
| `paths...` | Files or directories to scan for certificates and keystores. Supported formats: `.pem`, `.crt`, `.cer`, `.der`, `.pfx`, `.p12`. Zero or more paths may be provided; if none, the scan processes only system stores (with `--system-stores`). |

### Options

| Option | Description |
|--------|-------------|
| `--output <file>` | Write the CBOM JSON to this file instead of stdout. If not provided, the CBOM is written to standard output. |
| `--pfx-password-file <file>` | Path to a file containing the password for encrypted PFX/P12 keystores. The file should contain only the password; any trailing newline is stripped. Without this option, encrypted PFX/P12 files are skipped with a warning. |
| `--system-stores` | Also scan OS certificate stores. On Windows, scans the Personal (`My`), Trusted Root (`Root`), Intermediate/Certificate Authority (`CA`), and Trusted People (`TrustedPeople`) stores for both `CurrentUser` and `LocalMachine`. On non-Windows systems, scans the well-known PEM directories `/etc/ssl/certs` and `/etc/pki/tls/certs` when they exist. Unreadable or missing stores are skipped with a warning. |
| `--summary` | Print a post-quantum readiness summary table to stderr, showing counts of quantum-vulnerable, hybrid (transitional), and quantum-safe assets. |

## Guarantees

- **Read-only:** The scan never modifies any files or certificate stores.
- **Fully offline:** No network requests are made; the scan works in air-gapped environments.
- **No password prompts:** The scan never prompts interactively for passwords.
- **No private-key material emitted:** The CBOM contains only public-key metadata (algorithms, certificate subjects, key sizes). Private keys are never written to output.
- **Encrypted PFX handling:** Encrypted PFX/P12 keystores are only decrypted if `--pfx-password-file` is provided; otherwise they are skipped with a warning.

## Output Format

The output is a valid CycloneDX 1.6 (ECMA-424) JSON document describing:

- **Certificates:** X.509 certificates with subject name, issuer, validity dates, and algorithm references.
- **Algorithms:** Signature and public-key algorithms with OID and NIST post-quantum security level. Recognized algorithms include RSA and ECDSA (classical) and ML-DSA / SLH-DSA (post-quantum); unrecognized OIDs are still recorded, classified as `unknown`.
- **Public Keys:** RSA and EC keys, plus post-quantum signature keys (ML-DSA, SLH-DSA), with size (where applicable) and state.
- **Dependencies:** Logical relationships showing which algorithm and key each certificate uses.

The CBOM is consumable by any CycloneDX 1.6-aware tool, including bill-of-materials processors, software composition analysis (SCA) tools, and post-quantum migration planners.

## Example Invocation

### Basic scan of a directory

```bash
certifactory scan ./certs
```

Walks all `.pem`, `.crt`, `.cer`, `.der`, `.pfx`, and `.p12` files in `./certs` and prints the CBOM to stdout.

### Scan with system stores and summary

```bash
certifactory scan ./certs --system-stores --summary --output cbom.json
```

Scans both the `./certs` directory and the OS certificate stores, writes the CBOM to `cbom.json`, and prints a post-quantum readiness summary table to stderr.

### Scan encrypted PFX with password file

```bash
certifactory scan ./keystore.pfx --pfx-password-file password.txt --output cbom.json
```

Scans `./keystore.pfx` (decrypting it with the password from `password.txt`), writes the CBOM to `cbom.json`.

## Example CBOM Output

Below is a truncated example CBOM from a scan of a single RSA-4096 self-signed certificate:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-07-28T05:36:18Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "certifactory",
          "version": "1.0.0.0",
          "publisher": "Soverance Studios"
        }
      ]
    },
    "component": {
      "type": "platform",
      "bom-ref": "host:SOV-LAB",
      "name": "SOV-LAB"
    }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "alg:1.2.840.113549.1.1.11",
      "name": "RSA with SHA-256",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "signature",
          "nistQuantumSecurityLevel": 0
        },
        "oid": "1.2.840.113549.1.1.11"
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "alg:1.2.840.113549.1.1.1",
      "name": "RSA",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "nistQuantumSecurityLevel": 0
        },
        "oid": "1.2.840.113549.1.1.1"
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "cert:02d046fcfc98235a806508e045a8a6352bf6181376c46716f33168493b2a204b",
      "name": "CN=example.com",
      "cryptoProperties": {
        "assetType": "certificate",
        "certificateProperties": {
          "subjectName": "CN=example.com",
          "issuerName": "CN=example.com",
          "notValidBefore": "2026-07-27T05:36:10Z",
          "notValidAfter": "2046-07-23T05:36:10Z",
          "signatureAlgorithmRef": "alg:1.2.840.113549.1.1.11",
          "subjectPublicKeyRef": "key:02d046fcfc98235a806508e045a8a6352bf6181376c46716f33168493b2a204b",
          "certificateFormat": "X.509"
        }
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "key:02d046fcfc98235a806508e045a8a6352bf6181376c46716f33168493b2a204b",
      "name": "RSA public key",
      "cryptoProperties": {
        "assetType": "related-crypto-material",
        "relatedCryptoMaterialProperties": {
          "type": "public-key",
          "algorithmRef": "alg:1.2.840.113549.1.1.1",
          "size": 4096,
          "state": "active"
        }
      }
    }
  ],
  "dependencies": [
    {
      "ref": "cert:02d046fcfc98235a806508e045a8a6352bf6181376c46716f33168493b2a204b",
      "dependsOn": [
        "alg:1.2.840.113549.1.1.11",
        "key:02d046fcfc98235a806508e045a8a6352bf6181376c46716f33168493b2a204b"
      ]
    },
    {
      "ref": "key:02d046fcfc98235a806508e045a8a6352bf6181376c46716f33168493b2a204b",
      "dependsOn": [
        "alg:1.2.840.113549.1.1.1"
      ]
    }
  ]
}
```

### Summary Table

When `--summary` is used, stderr also contains:

```
Scanned 1 certificates | 1 keys | 2 distinct algorithms

Post-quantum readiness
  [!]    1 quantum-vulnerable
  [~]    0 hybrid (transitional)
  [ok]   0 quantum-safe
```

This table classifies each certificate and key:
- **[!] quantum-vulnerable:** Classical algorithms (RSA, DSA, ECDSA) with no post-quantum alternative.
- **[~] hybrid (transitional):** Certificates using hybrid signatures or hybrid key agreement (classical primary + PQ alternative).
- **[ok] quantum-safe:** Pure post-quantum algorithms (ML-DSA, SLH-DSA) with no classical fallback.

## Standards Compliance

The output is a valid **CycloneDX 1.6** (ECMA-424) document. The CycloneDX specification defines a standardized XML and JSON format for describing software bill of materials (SBOM) and cryptographic bills of materials (CBOM).

For more information on CycloneDX, see [https://cyclonedx.org/](https://cyclonedx.org/).

## Notes

- **Warnings:** Non-critical issues (e.g., duplicate certificates, skipped encrypted keystores) are printed to stderr as warnings; they do not affect the exit code.
- **No certificate validation:** The scan does not verify certificate chains or expiration dates; it inventories all certificates found.
- **Deterministic bom-refs:** Each certificate's and key's `bom-ref` is computed deterministically from the SHA-256 thumbprint of the certificate (DER encoding), and each algorithm's `bom-ref` from its OID, so that repeat scans of unchanged inputs produce identical asset identities.
