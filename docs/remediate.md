# remediate — Turn a CBOM into a Post-Quantum Remediation Playbook

## Purpose

The `remediate` command consumes a CycloneDX 1.6 Cryptographic Bill of Materials
(CBOM) — produced by `scan`, `tls-scan`, or any other CycloneDX-1.6-conformant
tool — and turns it into a **prioritized, actionable remediation playbook**.
Where `risk` answers *which of these vulnerable assets should I fix first?*,
`remediate` answers the next question: *what do I actually run to fix it, and
which assets aren't mine to fix at all?*

This is **advisory slice A** of the remediate loop: `remediate` recommends —
it prints Certifactory command hints you can copy and run yourself — but it
never re-issues a certificate on your behalf and never mutates its input CBOM.
A future slice B (`--generate`, roadmap below) will let `remediate` invoke the
reissue directly; slice C closes the loop by re-scanning and re-scoring after
migration. Neither exists yet.

`remediate` reuses `risk`'s scorer internally (it never modifies `RiskScorer`
or the scoring math — see [README.md, "Post-quantum risk scoring"](../README.md#post-quantum-risk-scoring))
so the same worst-first ordering and A–F grades apply here too; `remediate`
adds the *what to do about it* layer on top.

## Command Syntax

```
certifactory remediate [--input <cbom.json>] [--format table|json] [--report <path.md>] [--top <N>] [--quantum-year <YYYY>] [--data-shelf-life <years>] [--migration-time <years>]
```

`remediate` takes no positional arguments — it always operates on a whole CBOM
document, read either from a file or from standard input.

## The `scan | remediate` Pipeline

By default, `remediate` reads the CBOM JSON from **standard input**, so it
composes directly with the scan commands:

```bash
certifactory scan ./certs | certifactory remediate
certifactory tls-scan example.com:443 | certifactory remediate
```

To remediate a CBOM you already have saved to disk, pass `--input`:

```bash
certifactory remediate --input cbom.json
```

`remediate` treats the CBOM as **read-only** input — the only file it ever
writes is the optional `--report` Markdown output.

## Controllable vs. Vendor-Dependent

Every quantum-vulnerable asset in the CBOM lands in exactly one bucket:

| Bucket | Meaning |
|---|---|
| **Controllable** | You hold the private key (`certifactory:certificate:custody = owned-key`) — Certifactory can recommend a concrete reissue command. |
| **Vendor-dependent** | The certificate is a trust anchor you don't control the key for (`custody = public-only`) — e.g. a third-party root CA. No direct action; you're waiting on the vendor to ship a PQC root. |
| **Manual review** | The input CBOM has no custody enrichment at all (see "Custody degradation" below) — `remediate` can't tell which keys you hold, so it declines to guess. |
| **Already safe** | The asset is already hybrid or fully quantum-safe — nothing to do. |

Only third-party roots and vendor-controlled trust anchors are vendor-dependent;
your own self-signed CAs and leaf/server certs — anything Certifactory (or any
tool that recorded custody) saw the private key for — are controllable.

**Known limitation (PEM custody is file-level, not per-certificate):** for PEM
input, `scan` detects custody by checking whether the file contains any
`PRIVATE KEY` block at all — if it does, *every* certificate parsed out of
that file is recorded as `owned-key`, without matching each key to the
specific certificate it belongs to. This is a Slice-A simplification; PFX and
system-store custody are determined per-certificate and are exact.

## `AlgorithmPolicy` — Target Algorithm Precedence

For every **controllable** asset, `remediate` picks a recommended target
algorithm using a fixed, documented precedence (first match wins):

| Precedence | Condition | Target |
|---|---|---|
| 1 | Role is `root-ca` or `intermediate-ca` | `ml-dsa-65` |
| 2 | Non-CA, validity span ≥ **10 years**, and usage is `signature` | `slh-dsa-256s` |
| 3 | Everything else (leaf / TLS endpoint, or shorter-lived / key-establishment) | `hybrid` |

This is the single source of truth for the mapping; the same table is
reproduced in [README.md, "Post-quantum remediation playbook"](../README.md#post-quantum-remediation-playbook)
so it never drifts between the two documents. CA certificates get a
pure PQ signature algorithm (`ml-dsa-65`) since they don't need classical
interop with legacy peers the way a public-facing leaf does. Long-lived,
signature-only certificates get `slh-dsa-256s` (stateless, conservative,
appropriate for something that won't be reissued again soon). Everything
else — the common case, especially TLS-facing leaves — gets `hybrid` for
maximum compatibility during the transition.

Each recommendation comes with a copy-pasteable command hint, e.g.:

```
certifactory server "example.com" <password> <server-ip> <root-ca.pfx> <root-ca-pw> ./out --algorithm hybrid
certifactory ca "Example Root CA" <password> ./out --algorithm ml-dsa-65
```

## Arguments and Options

| Option | Description |
|---|---|
| `--input <file>` | (Optional) Read the CBOM from this file instead of standard input. |
| `--format table\|json` | (Optional) Console output format. `table` (default) prints a human-readable playbook headline plus the controllable worst-first list. `json` prints the full machine-readable plan: bucket counts, custody-enrichment flag, and every asset with its action, target algorithm, and command hint. |
| `--report <path.md>` | (Optional) In addition to the console output, write a shareable Markdown remediation report to this path. |
| `--top <N>` | (Optional) Limit the controllable action list (both the console table and the Markdown report) to the N highest-risk assets. Default: **20**. |
| `--quantum-year <YYYY>` | (Optional) Mosca time-horizon override, passed through to the underlying risk scoring. Only takes effect when paired with `--data-shelf-life`. |
| `--data-shelf-life <years>` | (Optional) Mosca time-horizon override. Only takes effect when paired with `--quantum-year`. |
| `--migration-time <years>` | (Optional) Mosca time-horizon override. Default: **1**. Only used when `--quantum-year` and `--data-shelf-life` are both supplied. |

See [README.md, "Post-quantum risk scoring"](../README.md#post-quantum-risk-scoring)
for exactly how the Mosca override changes the underlying scoring math that
drives `remediate`'s worst-first ordering.

There is no `--fail-over` in this slice — `remediate` is advisory, not a CI
gate. Use `risk --fail-over` for a CI gate on inventory risk.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success. The CBOM was parsed and a remediation plan was produced — regardless of how many assets ended up controllable, vendor-dependent, or in need of manual review. |
| `1` | The CBOM input (stdin or `--input` file) could not be parsed as valid CBOM JSON. An error is printed to stderr and no plan is produced. |

## Output Formats

### Console table (default)

Prints the playbook headline (`Remediation plan: N controllable · N
vendor-dependent · N manual-review · N already safe (N assets)`), a custody
note if the input CBOM lacked custody enrichment, and the top `--top`
controllable assets worst first, each with its target algorithm and a
copy-pasteable command hint.

### `--format json`

Prints the same plan as a single JSON object to stdout — bucket counts,
`custodyPresent`, `timestamp`, and an `assets` array where every asset
(controllable or not) carries its score, grade, action, target algorithm,
and command hint (`null` when the action isn't `ReissuePqc`). Intended for
tooling/automation rather than human reading.

### `--report <path.md>`

Independently of `--format`, writes a Markdown report to the given path: the
playbook headline, a "Controllable — Reissue as PQC" table (worst first, with
target algorithm and full command per row), and a "Monitoring" section
summarizing the vendor-dependent count. Useful for sharing a remediation plan
with people who won't run the CLI themselves.

## Custody Degradation on Un-enriched CBOMs

`scan`/`tls-scan` emit CBOMs enriched with a `certifactory:certificate:custody`
property (`owned-key` or `public-only`) recording — as a boolean fact only,
**never the key itself** — whether the loader saw a private key for that
certificate. `remediate` needs this to distinguish controllable assets from
vendor-dependent trust anchors.

If you remediate an **older** Certifactory CBOM (predating custody
enrichment) or a **third-party** CBOM that never had it, `remediate` still
works — every otherwise-actionable asset degrades to **manual review**
instead of being guessed at, because `remediate` cannot tell which keys you
hold. Both the console output and the Markdown report print a one-line note
when this happens. Re-run the scan with a current Certifactory `scan`/`tls-scan`
to populate custody and unlock accurate controllable/vendor-dependent
classification.

## Example Invocation

### Remediate the output of `scan` directly

```bash
certifactory scan ./certs | certifactory remediate
```

### Remediate a saved CBOM and write a shareable report

```bash
certifactory remediate --input cbom.json --report remediation-plan.md
```

### Machine-readable output for tooling

```bash
certifactory remediate --input cbom.json --format json
```

### Apply a Mosca time-horizon override to the underlying ordering

```bash
certifactory remediate --input cbom.json --quantum-year 2035 --data-shelf-life 10 --migration-time 2
```

## Example Console Table Output

```
Remediation plan: 2 controllable · 1 vendor-dependent · 0 manual-review · 1 already safe  (4 assets)

Controllable — fix these (worst first), top 2:
   88.0  [F]  CN=Example Root CA   reissue → ml-dsa-65
            certifactory ca "Example Root CA" <password> ./out --algorithm ml-dsa-65
   25.5  [B]  CN=example.com   reissue → hybrid
            certifactory server "example.com" <password> <server-ip> <root-ca.pfx> <root-ca-pw> ./out --algorithm hybrid
```

## Roadmap

- **Slice A (this document): advisory.** `remediate` scores, classifies
  custody, picks a target algorithm, and prints a command hint. It never
  writes anything except the optional `--report` Markdown file.
- **Slice B: `--generate`.** A future flag will let `remediate` invoke the
  recommended `certifactory ca`/`server`/`smime` reissue directly (with
  explicit confirmation), instead of just printing the command.
- **Slice C: closed loop.** After a generated reissue, automatically
  re-`scan` and re-`risk`/`remediate` the result to confirm the asset moved
  out of "controllable" and into "already safe" — turning remediation into a
  verifiable, repeatable loop rather than a one-shot suggestion.

Neither slice B nor slice C is implemented yet.

## Notes

- **Deterministic given the same input:** Remediating the same CBOM with the
  same options always produces the same plan; only the `timestamp` field
  varies (wall-clock at plan time), the same non-determinism pattern already
  used by `scan`/`tls-scan`/`risk`.
- **Read-only:** `remediate` never modifies the input CBOM; the only file it
  writes is `--report`.
- **Never emits private-key material:** custody is recorded and consumed as a
  boolean fact only.
- **Works on any CycloneDX 1.6 CBOM:** including CBOMs from tools other than
  Certifactory, as long as they carry recognizable algorithm OIDs / KEX group
  names / certificate properties. Un-enriched inputs simply fall back to
  manual-review as described above.
