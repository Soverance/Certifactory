# tls-scan — Probe TLS Endpoints and Emit a CycloneDX 1.6 CBOM

## Purpose

The `tls-scan` command probes TLS endpoints over the network to inventory negotiated protocol parameters, certificate chains, and key-exchange groups. It emits a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) describing each asset and classifying it by post-quantum readiness — helping you assess the TLS crypto posture of your infrastructure and prepare for the transition to post-quantum cryptography.

Unlike the `scan` command (which is fully offline and read-only over local files), `tls-scan` makes **outbound network connections** to the targets you specify. You must be **authorized** to scan those endpoints. The tool performs a TLS handshake, negotiates parameters, and captures the served certificate chain and negotiated key-exchange group.

## Command Syntax

```
certifactory tls-scan [targets...] [--targets-file <file>] [--output <file>] [--summary] [--timeout <seconds>] [--concurrency <n>]
```

## Arguments and Options

### Positional Arguments

| Argument | Description |
|----------|-------------|
| `targets...` | TLS endpoints as `host:port` pairs (e.g., `example.com:443`, `api.example.com:8443`). Zero or more targets may be provided; targets from `targets...` and `--targets-file` are combined and deduplicated. |

### Options

| Option | Description |
|--------|-------------|
| `--targets-file <file>` | Path to a file with one `host:port` target per line. Empty lines and lines starting with `#` (comments) are ignored. If neither `targets` nor `--targets-file` is provided, no error is raised — the command emits an empty CBOM (same behavior as the sibling `scan` command with no paths). |
| `--output <file>` | Write the CBOM JSON to this file instead of stdout. If not provided, the CBOM is written to standard output. |
| `--summary` | Print a post-quantum readiness summary table to stderr, showing counts of quantum-vulnerable, hybrid (transitional), and quantum-safe key-exchange groups and signatures. |
| `--timeout <seconds>` | Per-target handshake timeout in seconds (default: 10). If a target does not complete the TLS handshake within this time, it is recorded as unreachable and processing moves to the next target. |
| `--concurrency <n>` | Maximum number of concurrent handshakes (default: 8). Controls parallelism when scanning multiple targets; increase for faster scans of many endpoints, decrease to reduce load. |

## Network and Authorization Posture

**Important:** `tls-scan` is **not offline**:
- It makes outbound TCP connections to each target on the specified port.
- You **must be authorized** to scan those endpoints (explicit permission from the endpoint owner).
- The tool is intended for authorized security testing and infrastructure inventory — not for scanning third-party endpoints without consent.

The scan is **read-only** in that it never modifies the remote server or sends any data beyond a standard TLS ClientHello. No authentication is performed; the handshake captures public-facing information (certificates, negotiated parameters).

## How PQ Key-Exchange Detection Works

Certifactory's `tls-scan` detects whether a server will negotiate a hybrid (quantum-safe) key-exchange group:

1. **Offer:** The tool constructs a TLS 1.3 ClientHello listing both classical and hybrid key-exchange groups (e.g., x25519, x25519mlkem768).
2. **Negotiate:** The server responds with its ServerHello, selecting one group.
3. **Classify:** The tool records which group the server chose:
   - If it selected a **hybrid group** (e.g., `x25519mlkem768`), the connection is marked as quantum-safe for key agreement.
   - If it selected only a **classical group** (e.g., `x25519`), the connection is marked as vulnerable.
   - If the server rejected all offers and closed the connection, the endpoint is marked as unreachable.

The handshake is **not completed** — the tool captures and discards the server's ServerHello without computing the session key or sending a Finished message. This minimizes the load on the scanned endpoint.

## Output Format

The output is a valid CycloneDX 1.6 (ECMA-424) JSON document describing:

- **Certificates:** The X.509 certificate chain served by the endpoint, with subject name, issuer, validity dates, and signature algorithm.
- **Key-Exchange Algorithms:** The negotiated key-exchange group (e.g., x25519mlkem768), classified by post-quantum readiness.
- **Signature Algorithms:** Algorithms used by the served certificates.
- **Protocol Asset:** A logical representation of the TLS session (version, cipher suites, key-exchange group).
- **Dependencies:** Logical relationships showing which algorithms and certificates are used by the protocol.

The CBOM is consumable by any CycloneDX 1.6-aware tool, including bill-of-materials processors, software composition analysis (SCA) tools, and post-quantum migration planners.

## Example Invocation

### Scan a single endpoint

```bash
certifactory tls-scan cloudflare.com:443 --output cbom.json
```

Probes cloudflare.com on port 443, writes the CBOM to `cbom.json`.

### Scan multiple endpoints with summary

```bash
certifactory tls-scan example.com:443 api.example.com:8443 --summary --output cbom.json
```

Probes two endpoints, writes the CBOM to `cbom.json`, and prints a post-quantum readiness summary to stderr.

### Scan endpoints from a file

```bash
certifactory tls-scan --targets-file targets.txt --output cbom.json
```

Reads targets from `targets.txt` (one `host:port` per line, comments prefixed with `#`), probes all endpoints concurrently (8 at a time by default), writes the CBOM to `cbom.json`.

### Scan with custom timeout and concurrency

```bash
certifactory tls-scan --targets-file targets.txt --timeout 5 --concurrency 16 --summary --output cbom.json
```

Scans endpoints from `targets.txt` with a 5-second per-target timeout and up to 16 concurrent handshakes, writes the CBOM and a summary to stderr.

## Example CBOM Output

Below is a truncated example CBOM from a live scan of `cloudflare.com:443`, showing the hybrid key-exchange group negotiated, the served certificate, and the cipher suite:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-07-28T21:33:07Z",
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
      "bom-ref": "alg:kex:x25519mlkem768",
      "name": "X25519MLKEM768",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "key-agree",
          "nistQuantumSecurityLevel": 3
        }
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "cert:6a7041850081b32dbe52400df0a2842c32d55e80ffa40e339f7c1508a913d3f4",
      "name": "CN=cloudflare.com",
      "cryptoProperties": {
        "assetType": "certificate",
        "certificateProperties": {
          "subjectName": "CN=cloudflare.com",
          "issuerName": "C=US,O=Google Trust Services,CN=WE1",
          "notValidBefore": "2026-07-08T21:47:39Z",
          "notValidAfter": "2026-10-06T22:47:27Z",
          "signatureAlgorithmRef": "alg:1.2.840.10045.4.3.2",
          "subjectPublicKeyRef": "key:6a7041850081b32dbe52400df0a2842c32d55e80ffa40e339f7c1508a913d3f4",
          "certificateFormat": "X.509"
        }
      }
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "protocol:tls:cloudflare.com:443",
      "name": "TLS 1.3 @ cloudflare.com:443",
      "cryptoProperties": {
        "assetType": "protocol",
        "protocolProperties": {
          "type": "tls",
          "version": "1.3",
          "cipherSuites": [
            {
              "name": "TLS_AES_128_GCM_SHA256"
            }
          ]
        }
      }
    }
  ],
  "dependencies": [
    {
      "ref": "protocol:tls:cloudflare.com:443",
      "dependsOn": [
        "alg:kex:x25519mlkem768",
        "cert:6a7041850081b32dbe52400df0a2842c32d55e80ffa40e339f7c1508a913d3f4"
      ]
    }
  ]
}
```

In this example, `cloudflare.com:443` negotiated the hybrid key-exchange group `X25519MLKEM768` (NIST quantum security level 3), indicating the endpoint is quantum-safe for key agreement. The served certificate is an ECDSA P-256 cert signed with SHA-256 (classical signature algorithm).

### Summary Table

When `--summary` is used, stderr also contains (this is the same `ScanSummary` renderer used by the `scan` command, with a TLS endpoints block appended when any TLS targets were scanned):

```

Scanned 1 certificates | 1 keys | 2 distinct algorithms

Post-quantum readiness
  [!]    1 quantum-vulnerable
  [~]    0 hybrid (transitional)
  [ok]   0 quantum-safe

TLS endpoints (1 scanned)
  [!]    0 quantum-vulnerable key exchange
  [~]    1 hybrid key exchange (transitional)
  [ok]   0 quantum-safe key exchange
```

- **`Post-quantum readiness`** classifies every certificate discovered (from the served chains of all scanned endpoints) by the signature/public-key algorithm(s) it depends on:
  - **[!] quantum-vulnerable:** The certificate's signature or public-key algorithm is classical (e.g., RSA, ECDSA) with no post-quantum alternative present.
  - **[~] hybrid (transitional):** The certificate has both a classical and a post-quantum algorithm reference.
  - **[ok] quantum-safe:** The certificate depends only on post-quantum algorithms.
- **`TLS endpoints`** classifies each successfully-probed endpoint by the key-exchange group it negotiated:
  - **[!] quantum-vulnerable key exchange:** The server negotiated only a classical group (e.g., x25519) or an unrecognized group.
  - **[~] hybrid key exchange (transitional):** The server negotiated a hybrid group (e.g., x25519mlkem768).
  - **[ok] quantum-safe key exchange:** The server negotiated a pure post-quantum group (e.g., mlkem768).

## Key-Exchange Classification Legend

The following table shows how `tls-scan` classifies TLS key-exchange groups by post-quantum readiness:

| Group Name | Display Name | Classification | NIST Level | Notes |
|---|---|---|---|---|
| `x25519` | X25519 | Quantum-vulnerable | 0 | Classical elliptic curve. Vulnerable to Shor's algorithm. |
| `x448` | X448 | Quantum-vulnerable | 0 | Classical elliptic curve. Vulnerable to Shor's algorithm. |
| `secp256r1` | secp256r1 (P-256) | Quantum-vulnerable | 0 | Classical NIST P-256. Vulnerable to Shor's algorithm. |
| `secp384r1` | secp384r1 (P-384) | Quantum-vulnerable | 0 | Classical NIST P-384. Vulnerable to Shor's algorithm. |
| `secp521r1` | secp521r1 (P-521) | Quantum-vulnerable | 0 | Classical NIST P-521. Vulnerable to Shor's algorithm. |
| `ffdhe2048` | ffdhe2048 | Quantum-vulnerable | 0 | Classical Finite Field Diffie-Hellman (2048-bit). |
| `ffdhe3072` | ffdhe3072 | Quantum-vulnerable | 0 | Classical Finite Field Diffie-Hellman (3072-bit). |
| `ffdhe4096` | ffdhe4096 | Quantum-vulnerable | 0 | Classical Finite Field Diffie-Hellman (4096-bit). |
| `ffdhe6144` | ffdhe6144 | Quantum-vulnerable | 0 | Classical Finite Field Diffie-Hellman (6144-bit). |
| `ffdhe8192` | ffdhe8192 | Quantum-vulnerable | 0 | Classical Finite Field Diffie-Hellman (8192-bit). |
| `x25519mlkem768` | X25519MLKEM768 | Hybrid (Transitional) | 3 | Classical X25519 + ML-KEM-768. Transitional; both present. |
| `secp256r1mlkem768` | SecP256r1MLKEM768 | Hybrid (Transitional) | 3 | Classical P-256 + ML-KEM-768. Transitional; both present. |
| `secp384r1mlkem1024` | SecP384r1MLKEM1024 | Hybrid (Transitional) | 5 | Classical P-384 + ML-KEM-1024. Transitional; both present. |
| `x25519kyber768` | X25519Kyber768Draft00 | Hybrid (Transitional) | 3 | Classical X25519 + Kyber-768 (draft). Transitional; both present. |
| `mlkem768` | ML-KEM-768 | Quantum-safe (Pure PQ) | 3 | FIPS 203 ML-KEM-768. Pure post-quantum; no classical fallback. |
| `mlkem1024` | ML-KEM-1024 | Quantum-safe (Pure PQ) | 5 | FIPS 203 ML-KEM-1024. Pure post-quantum; no classical fallback. |

**Classification Semantics:**
- **Quantum-vulnerable:** Classical groups broken by quantum computers running Shor's algorithm. All classical Diffie-Hellman and elliptic-curve groups fall here.
- **Hybrid (Transitional):** Combine a classical group with a post-quantum algorithm (e.g., X25519MLKEM768). Both are present; the connection is secure as long as one is unbroken. Used during the migration period.
- **Quantum-safe (Pure PQ):** Post-quantum algorithms only (ML-KEM). No classical fallback; secure against both classical and quantum adversaries.

Unknown groups (not listed above) are classified as `NotApplicable` and do not affect post-quantum readiness counts.

## Standards Compliance

The output is a valid **CycloneDX 1.6** (ECMA-424) document. The CycloneDX specification defines a standardized XML and JSON format for describing software bill of materials (SBOM) and cryptographic bills of materials (CBOM).

For more information on CycloneDX, see [https://cyclonedx.org/](https://cyclonedx.org/).

## Deferred Features

The following features are **not yet implemented** and are planned for future releases:

- **STARTTLS support:** Currently, only direct TLS connections (e.g., HTTPS on port 443) are supported. STARTTLS for protocols like SMTP, IMAP, FTP (ports 25, 143, 21) is deferred.
- **Supported-suite enumeration:** The `--enumerate` flag (to probe which cipher suites and key-exchange groups a server supports) is not yet implemented. Current behavior scans only what the server negotiates in a single handshake.

## Notes

- **Connection attempts:** The tool attempts one TLS handshake per target. If the handshake times out or fails, the target is recorded as unreachable; subsequent targets continue processing.
- **Handshake optimization:** The handshake is not fully completed (no Finished message sent). The tool captures the ServerHello, certificate chain, and negotiated parameters, then closes the connection.
- **Certificate chain:** All certificates in the served chain (leaf + intermediates) are recorded in the CBOM. The root CA (if self-signed) may not be included if the server does not send it.
- **Deterministic bom-refs:** Certificate `bom-ref` values are computed deterministically from the SHA-256 thumbprint, so repeat scans of the same endpoints produce identical asset identities (useful for tracking changes over time).
- **No certificate validation:** The scan does not verify certificate chains or expiration dates; it inventories all certificates served by the endpoint, including expired or self-signed ones.
