# DepSentry

**Reachability-aware software supply chain risk analyzer.**

Conventional dependency scanners flag a vulnerability whenever a vulnerable
*package version* is installed. DepSentry additionally asks whether the
*vulnerable function inside it* can actually be reached from your code — and
attaches the call path as evidence.

> Semester VII Integrated Project (Industry / Research-Oriented)
> Symbiosis Skills & Professional University, Pune — AY 2026–27
> Per Notification 7, Annexure-A (Ref. SSPU/RO/2026-27/2921)

---

## The problem, in one example

Your app depends on PyYAML 5.4.1. An advisory reports arbitrary code execution,
**CVSS 9.8**, in `yaml.load()`. Every scanner raises a CRITICAL and fails your
build.

Your app only calls `yaml.safe_load()`.

The finding is real, correctly matched, and completely meaningless. DepSentry
suppresses it — and tells you why — while surfacing the CVSS 7.5 finding in the
same project that *is* on a live path.

## Results

Measured on a labelled 40-project benchmark (259 advisory instances, 33.2% truly
exploitable):

| | Alerts shown | Precision | Recall | F1 |
|---|---|---|---|---|
| **DepSentry** | **80** | **1.000** | 0.930 | **0.964** |
| CVSS ≥ 7.0 gate | 107 | 0.318 | 0.395 | 0.352 |
| No triage | 259 | 0.332 | 1.000 | 0.499 |

- **25.2%** fewer alerts than a CVSS gate, with **zero false positives**
- Ranking quality **MAP 0.950 vs 0.512**
- **Two thirds** of matched advisories were unreachable

⚠ These figures come from a synthetic benchmark and measure implementation
correctness, not real-world accuracy. See
[`docs/05_results_and_discussion.md`](docs/05_results_and_discussion.md) §5.6.

## Quick start

```bash
python3 -m pip install -r requirements.txt

./run.sh setup      # seed advisory DB + generate benchmark
./run.sh test       # 56 tests
./run.sh demo       # the PyYAML example, live
./run.sh evaluate   # reproduce the research results
./run.sh dashboard  # interactive UI
./run.sh build-viz  # compile the Rust 3D engine
./run.sh viz        # 3D attack surface
```

Python 3.11+ (needs `tomllib`).

## Scan your own project

```bash
export PYTHONPATH=src
python3 -m depsentry.cli scan /path/to/project --out reports --fail-on 7.0
```

Exit code `1` if an actionable finding breaches the threshold, `0` otherwise.
Unreachable findings never break a build.

## How it works

```
project ──▶ SBOM ──▶ advisory match ──▶ call graph ──▶ reachability ──▶ risk ──▶ report
            sbom.py     vulndb.py       callgraph.py   reachability.py  risk.py  report.py
```

Each finding gets one of four verdicts:

| Verdict | Meaning | Weight |
|---|---|---|
| `REACHABLE` | Path exists from an entrypoint — evidence attached | 1.0 |
| `POTENTIALLY_REACHABLE` | `getattr`/`eval` defeats static analysis | 0.6 |
| `UNKNOWN` | Advisory names no symbol — nothing to trace | 0.4 |
| `UNREACHABLE` | Imported, but the symbol is demonstrably never called | 0.1 |

Risk fuses severity with context, multiplicatively so reachability can dominate:

```
risk = CVSS × reachability × exposure × dep_depth × fix_available × exploit_known
```

An unreachable CVSS 9.8 scores 0.98. A reachable CVSS 5.0 scores 5.0. That
inversion is the point.

**Two states never claim safety.** `UNKNOWN` and `POTENTIALLY_REACHABLE` both
mean *the analysis cannot prove this is safe*, so it doesn't say so.

## 3D attack surface

```bash
./run.sh build-viz     # compile the Rust engine (once)
./run.sh viz           # render and open
```

A force-directed dependency graph where the **layout, camera, perspective
projection and depth sorting all run in Rust compiled to WebAssembly** — the
browser only rasterises the float buffers Rust writes. 29 KB wasm, base64-inlined
into the page, so it works offline and from `file://`.

- 🔴 **red, pulsing** — vulnerable symbol reachable from an entrypoint; the whole
  chain from your application to the package ignites
- 🟡 **amber** — vulnerable but never called, suppressed
- 🔵 **blue** — clean dependency

Drag to rotate, scroll to zoom, hover for detail. On the bundled showcase app:
27 packages, 20 findings, 3 reachable, **85% noise reduction**.

The engine has a headless test (`node viz/smoke.mjs <wasm>`) that runs 240 frames
and asserts the buffers stay finite and the depth order stays sorted — a
numerical blow-up otherwise shows up only as a blank canvas.

Rust is **optional**: if the wasm is missing, the 3D tab shows a build hint and
everything else works unchanged.

## Live data (all opt-in, all degrade cleanly)

```bash
./run.sh scan-live ./myproject          # real OSV.dev advisories + EPSS
python3 -m depsentry.cli scan . --live --overlay-heuristic
python3 -m depsentry.cli scan . --remediation-limit 10   # needs ANTHROPIC_API_KEY
```

| Flag | What it adds |
|---|---|
| `--live` | Real advisories from OSV.dev. Falls back to the local corpus if unreachable. |
| `--cache` | Stores fetched advisories locally for offline reuse. |
| `--overlay-heuristic` | Supplies symbols for advisories that carry none — see the caveat below. |
| `--no-epss` | Skips exploit-probability lookup (on by default with `--live`). |
| `--remediation-limit N` | AI fix guidance for the top N reachable findings. |
| `--no-llm` / `--no-vex` | Hard off switches. |

⚠ **Measured, and it matters: OSV's PyPI advisories carry no symbol data — 0 of
171 sampled.** Go's vulndb populates it well; Python's sources do not populate it
at all. Without the overlay, a live PyPI scan yields only UNKNOWN verdicts and
reachability contributes nothing. The overlay is a curated *guess*, so it is
off by default, recorded per finding in `symbol_source`, and reported in the
coverage summary on every live scan. Full analysis:
[`docs/05`](docs/05_results_and_discussion.md) §5.5b.

## Outputs

- **Markdown** — human review, including a full audit trail of suppressions
- **SARIF 2.1.0** — with `codeFlows`, so GitHub renders the reachability path natively
- **OpenVEX 0.2.0** — machine-readable "not affected, and here's why", derived rather than asserted
- **CycloneDX 1.5** — SBOM interchange, optionally Ed25519-signed
- **JSON** — programmatic use

## Security properties

| Control | Mechanism |
|---|---|
| SBOM tamper-evidence | Ed25519 detached signature, HMAC-SHA256 fallback |
| Audit trail integrity | Append-only SHA-256 hash chain; edits and deletions both detected |
| API path traversal | Scans confined to an allow-listed root |
| SQL injection | Parameterised queries throughout |
| Analysing hostile code | **Static analysis only** — never imports or executes the target |

## Documentation

| Document | Contents |
|---|---|
| [`00_SOP_COMPLIANCE.md`](docs/00_SOP_COMPLIANCE.md) | Every SOP clause → its artifact |
| [`01_problem_statement.md`](docs/01_problem_statement.md) | Problem, literature survey, objectives, hypotheses |
| [`02_subject_contribution_matrix.md`](docs/02_subject_contribution_matrix.md) | Subject mapping, NOS, CO/PO/PSO |
| [`03_design_document.md`](docs/03_design_document.md) | Architecture, algorithm, threat model |
| [`04_implementation_details.md`](docs/04_implementation_details.md) | How it's built, and what broke |
| [`05_results_and_discussion.md`](docs/05_results_and_discussion.md) | Results, ablation, threats to validity |
| [`06_final_project_report.md`](docs/06_final_project_report.md) | Report + 10-minute demo script |
| [`07_source_code_guide.md`](docs/07_source_code_guide.md) | Code tour and extension points |
| [`08_appendix.md`](docs/08_appendix.md) | Glossary, references, ethics, checklist |
| [`review_tracker.md`](docs/review_tracker.md) | Progress Reviews 1–3 |
| [`logbook.md`](docs/logbook.md) | Session log, including bugs and a negative result |

## Data disclosure

The advisory corpus uses **`DEPS-` identifiers, not `CVE-` identifiers**. The
advisories are modelled on the structure of real OSV records but are **not
claims about real defects in the named packages**. To use genuine data, export
from osv.dev and load it with `VulnerabilityDB.import_osv()` — no other change
is required.

## License

MIT — see [LICENSE](LICENSE).
