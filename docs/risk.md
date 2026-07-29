# risk — Score a CBOM for Post-Quantum Risk

## Purpose

The `risk` command consumes a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) — produced by `scan`, `tls-scan`, or any other CycloneDX-1.6-conformant tool — and turns it into a **prioritized post-quantum risk assessment**. Where `scan`/`tls-scan` classify each asset into a flat bucket (quantum-vulnerable / hybrid / quantum-safe), `risk` answers the harder question: *which of these vulnerable assets should I fix first?*

Each certificate and TLS endpoint in the CBOM gets a **0–100 risk score** (higher = more urgent) and an **A–F grade**, derived from a documented, zero-config heuristic (gate-and-amplify: post-quantum readiness gates the score, harvest-now-decrypt-later exposure amplifies it). Per-asset scores roll up into a single **inventory grade** so you have one number to track over time, plus a worst-first list so nothing gets lost in the average.

The complete scoring ruleset — every weight and threshold — is documented in the top-level [README.md, "Post-quantum risk scoring"](../README.md#post-quantum-risk-scoring) section, not duplicated here, so there is exactly one place to look when you need to defend or cite a score.

## Command Syntax

```
certifactory risk [--input <cbom.json>] [--format table|json] [--report <path.md>] [--top <N>] [--quantum-year <YYYY>] [--data-shelf-life <years>] [--migration-time <years>] [--fail-over <score>]
```

`risk` takes no positional arguments — it always operates on a whole CBOM document, read either from a file or from standard input.

## Input: stdin by default, or `--input <file>`

By default, `risk` reads the CBOM JSON from **standard input**. This is what makes it composable with the scan commands:

```bash
certifactory scan ./certs | certifactory risk
certifactory tls-scan example.com:443 | certifactory risk
```

To score a CBOM you already have saved to disk (from a previous scan, or from a third-party CycloneDX 1.6 producer), pass `--input`:

```bash
certifactory risk --input cbom.json
```

`risk` treats the CBOM as read-only input — it never writes scores back into the CBOM file itself.

## Arguments and Options

| Option | Description |
|---|---|
| `--input <file>` | (Optional) Read the CBOM from this file instead of standard input. |
| `--format table\|json` | (Optional) Console output format. `table` (default) prints a human-readable, worst-first summary. `json` prints the full machine-readable assessment: inventory score/grade, per-band counts, and every scored asset with its factor breakdown. |
| `--report <path.md>` | (Optional) In addition to the console output, write a shareable Markdown risk report to this path — suitable for leadership / compliance audiences. |
| `--top <N>` | (Optional) Limit the prioritized asset list (both the console table and the Markdown report) to the N highest-risk assets. Default: **20**. |
| `--quantum-year <YYYY>` | (Optional) Mosca time-horizon override: the estimated calendar year a cryptographically-relevant quantum computer (CRQC) arrives. Only takes effect when paired with `--data-shelf-life`. |
| `--data-shelf-life <years>` | (Optional) Mosca time-horizon override: how many years the data an asset protects must remain confidential. Only takes effect when paired with `--quantum-year`. |
| `--migration-time <years>` | (Optional) Mosca time-horizon override: years required to complete the PQ migration once started. Default: **1**. Only used when `--quantum-year` and `--data-shelf-life` are both supplied. |
| `--fail-over <score>` | (Optional) CI gate: if the inventory score exceeds this value, `risk` exits with code `2` instead of `0`. |

See [README.md, "Post-quantum risk scoring"](../README.md#post-quantum-risk-scoring) for exactly how `--quantum-year`/`--data-shelf-life`/`--migration-time` change the scoring math (the Mosca override).

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success. The CBOM was parsed and scored — regardless of how risky the resulting assessment is — and (if `--fail-over` was given) the inventory score did not exceed the threshold. |
| `1` | The CBOM input (stdin or `--input` file) could not be parsed as valid CBOM JSON. An error is printed to stderr and nothing is scored. |
| `2` | `--fail-over <score>` was supplied and the inventory score exceeded it. A gate-failure message (`Risk gate failed: inventory score X > Y`) is printed to stderr. Use this in CI to fail a build/pipeline when your cryptographic inventory's risk regresses past a threshold. |

## Output Formats

### Console table (default)

Prints the inventory headline (score, grade, per-band counts) followed by the top `--top` assets, worst first, each annotated with its top 1–2 human-readable risk drivers.

### `--format json`

Prints the same assessment as a single JSON object to stdout — `inventoryScore`, `grade`, `gradeLabel`, `timestamp`, `enrichmentPresent`, per-grade `bandCounts`, and an `assets` array where each entry carries its score, grade, drivers, and the full four-factor breakdown (`usage`, `role`, `validity`, `keyStrength`, `exposure`, `readinessFactor`). Intended for tooling/automation rather than human reading.

### `--report <path.md>`

Independently of `--format`, writes a Markdown report to the given path: a headline grade, a posture/band-count table, a worst-first prioritized remediation table, and a methodology footnote pointing back to the README ruleset. Useful for sharing a point-in-time assessment with people who won't run the CLI themselves.

## Example Invocation

### Score the output of `scan` directly

```bash
certifactory scan ./certs | certifactory risk
```

### Score a saved CBOM and write a leadership report

```bash
certifactory risk --input cbom.json --report risk-report.md
```

### Machine-readable output for tooling

```bash
certifactory risk --input cbom.json --format json
```

### CI gate — fail the build if risk gets too high

```bash
certifactory scan ./certs | certifactory risk --fail-over 40
```

Exits `2` (failing the pipeline step) if the inventory score is above 40 (worse than grade B).

### Apply a Mosca time-horizon override

```bash
certifactory risk --input cbom.json --quantum-year 2035 --data-shelf-life 10 --migration-time 2
```

Reinterprets the validity factor: if the data an asset protects (10 years of confidentiality + 2 years to migrate = a 12-year horizon) would still need to be secret when a CRQC is expected to arrive (2035), that asset's validity factor saturates to the maximum.

## Example Console Table Output

```
Post-quantum risk: 37.8/100  Grade B (Guarded)
  F 1  D 0  C 0  B 1  A 1   (3 assets)

Top 3 by risk:
   88.0  [F]  CN=root — quantum-vulnerable algorithm, harvest-now-decrypt-later exposure
   25.5  [B]  CN=leaf — quantum-vulnerable algorithm
    0.0  [A]  CN=safe
```

This example inventory has a vulnerable root CA in RSA-4096 with key-establishment usage (score 88, grade F/Critical), a vulnerable RSA leaf used only for signatures and expiring soon (score 25.5, grade B/Guarded), and an already-migrated quantum-safe leaf (score 0, grade A/Low). The inventory score (37.8) is the mean of the three.

## Example Markdown Report Snippet

```markdown
# Post-Quantum Risk Report

**Grade B (Guarded)** — inventory score **37.8/100**
Assessed 2026-07-28T12:00:00Z · 3 assets

## Posture

| Grade | Label | Count |
|---|---|---|
| F | Critical | 1 |
| D | High | 0 |
| C | Elevated | 0 |
| B | Guarded | 1 |
| A | Low | 1 |

## Prioritized Remediation

| # | Score | Grade | Asset | Type | Top risk drivers |
|---|---|---|---|---|---|
| 1 | 88.0 | F | CN=root | certificate | quantum-vulnerable algorithm; harvest-now-decrypt-later exposure |
| 2 | 25.5 | B | CN=leaf | certificate | quantum-vulnerable algorithm |
| 3 | 0.0 | A | CN=safe | certificate |  |

## Methodology

Score = `100 × readinessFactor × exposure`, where exposure weights HNDL usage (0.40), asset role (0.25), validity window (0.20), and key strength (0.15). See the Certifactory README, "Post-quantum risk scoring", for the full ruleset.
```

## Graceful Degradation on Un-enriched CBOMs

`scan`/`tls-scan` emit CBOMs enriched with two Certifactory-specific properties that `risk` needs for full accuracy: `certifactory:certificate:role` (root-ca / intermediate-ca / leaf) and `certifactory:key:usage` (derived from the X.509 KeyUsage extension). If you score an **older** Certifactory CBOM (predating this enrichment) or a **third-party** CBOM that never had it, `risk` still works — it falls back to conservative, worst-case defaults rather than erroring or under-scoring. Both the console output and the Markdown report print a one-line note when this happens. Full details are in the README ruleset section linked below.

## Full Scoring Ruleset

This document covers the command's *interface*. The command's *scoring math* — the `readinessFactor` table, the four weighted exposure factors and their exact tier thresholds, the grade bands, the harvest-now-decrypt-later (HNDL) rationale, the Mosca time-horizon override, and the graceful-degradation defaults — is documented in full in [README.md, "Post-quantum risk scoring"](../README.md#post-quantum-risk-scoring). That is the single authoritative reference; refer to it (rather than re-deriving the numbers) when citing or defending a score.

## Notes

- **Deterministic given the same input:** Scoring the same CBOM with the same options always produces the same scores; only the `timestamp` field varies (wall-clock at scoring time), the same non-determinism pattern already used by `scan`/`tls-scan`.
- **Heuristic, not certification:** The score is a prioritization aid grounded in a documented, transparent heuristic — it is not a compliance attestation or a formal risk quantification.
- **Read-only:** `risk` never modifies the input CBOM; writing scores back into the CBOM (`--annotate`) is a possible future addition, not implemented in this version.
- **Works on any CycloneDX 1.6 CBOM:** including CBOMs from tools other than Certifactory, as long as they carry recognizable algorithm OIDs / KEX group names / certificate properties. Un-enriched inputs simply fall back to the conservative defaults described above.
