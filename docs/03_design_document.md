# 3. Design Document

SOP clause 9 Phase 2 (Design and Planning) and clause 12 item 3.

---

## 3.1 Design goals

| Goal | Rationale | How it constrains the design |
|---|---|---|
| **G1 Auditable suppression** | Hiding a finding is a security decision. If it cannot be reviewed, it cannot be trusted. | Suppressed findings are never deleted — they are listed with the reason. Every REACHABLE verdict carries a call path. |
| **G2 Fail safe, not silent** | An analyser that cannot prove safety must not claim it. | Advisories with no symbol data → UNKNOWN, not UNREACHABLE. Dynamic dispatch → POTENTIALLY_REACHABLE. |
| **G3 Offline by default** | Must run in air-gapped CI and be reproducible by an examiner. | SQLite advisory store; no network calls in the scan path. |
| **G4 Reproducible** | A research claim that cannot be re-run is not a claim. | Seeded corpus generation; deterministic SBOM canonicalisation. |
| **G5 CI-native** | Industry relevance requires consumability. | SARIF output; exit-code gate; unreachable findings demoted to `note`. |

## 3.2 System architecture

```
                        ┌──────────────────────────┐
   project source ─────▶│  1. SBOM Generator       │  sbom.py
   requirements.txt     │     direct + transitive  │
                        └───────────┬──────────────┘
                                    │ list[Package]
                                    ▼
                        ┌──────────────────────────┐
   advisory corpus ────▶│  2. Advisory Matcher     │  vulndb.py
   (SQLite, OSV shape)  │     version-range join   │
                        └───────────┬──────────────┘
                                    │ list[(Package, Vulnerability)]
                                    ▼
   project source ─────▶┌──────────────────────────┐
                        │  3. Call Graph Builder   │  callgraph.py
                        │     AST + import table   │
                        └───────────┬──────────────┘
                                    │ CallGraph + entrypoints
                                    ▼
                        ┌──────────────────────────┐
                        │  4. Reachability Engine  │  reachability.py
                        │     BFS, symbol matching │
                        └───────────┬──────────────┘
                                    │ Finding + verdict + CallPath
                                    ▼
                        ┌──────────────────────────┐
                        │  5. Risk Fusion & Rank   │  risk.py
                        └───────────┬──────────────┘
                                    │ ranked list[Finding]
                                    ▼
                        ┌──────────────────────────┐
                        │  6. Integrity & Report   │  integrity.py, report.py
                        │     sign, hash-chain     │
                        └───────────┬──────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
        CLI (exit code)        REST API              Dashboard
        SARIF / CycloneDX      api/main.py           dashboard/app.py
```

`pipeline.py` orchestrates stages 1–6; each stage is independently testable.

## 3.3 Data model

```
Package      name, version, ecosystem, direct, parents[], license, sha256
                └─ purl, depth

Vulnerability vuln_id, package, introduced, fixed, cvss_score, cvss_vector,
              summary, affected_symbols[], cwe[], exploit_known, network_exposed
                └─ severity (derived), has_fix (derived)

CallPath     entrypoint, steps[], target_symbol, confidence
                └─ render() → "main -> handler -> yaml.load"

Finding      Vulnerability × Package
             + reachability, call_paths[], risk_score, baseline_score,
               rank, rationale[]
                └─ actionable (derived)

SBOM         project, packages[], signature
                └─ to_cyclonedx(), canonical_bytes()

ScanResult   project, sbom, findings[], entrypoints[], stats
                └─ actionable_findings, noise_reduction()
```

Design note: `canonical_bytes()` deliberately **excludes the timestamp** so an
unchanged dependency set produces an identical digest. Without that, every
regeneration would appear to be a change, and signature comparison would be
useless for drift detection.

## 3.4 The reachability decision procedure

The core algorithm. Evaluated in order; first match wins.

| # | Condition | Verdict | Weight | Reasoning |
|---|---|---|---|---|
| 1 | Package never imported in any project module | UNREACHABLE | 0.1 | Installed but unused — cannot execute |
| 2 | Advisory names no affected symbol | **UNKNOWN** | 0.4 | Nothing to trace. Absence of evidence is not evidence of absence (G2) |
| 3 | Vulnerable symbol lies on a path from an entrypoint | REACHABLE | 1.0 | Path is attached as evidence |
| 4 | Imported, symbol not called, but importing module uses `getattr`/`eval` | POTENTIALLY_REACHABLE | 0.6 | Static analysis defeated; cannot claim safety (G2) |
| 5 | Imported, symbol demonstrably not called | UNREACHABLE | 0.1 | The interesting case — the PyYAML example |

**Weight is never zero.** Even UNREACHABLE keeps 0.1, so a sufficiently severe
finding can still surface. Zero would make suppression absolute, and the
analysis is not good enough to justify that.

### Symbol matching rules

Matching must be precise or the whole result is worthless — `yaml.safe_load`
matching an advisory on `yaml.load` would invert the headline finding.

1. **Exact match** — `yaml.load` == `yaml.load` ✔
2. **Alias-equivalent** — same package root *and* same final attribute, catching
   the same function reached through a different import alias
3. **Class-method** — reached symbol starts with `advisory_symbol + "."`
4. **Everything else** — no match. `yaml.safe_load` vs `yaml.load`: same root,
   different tail → **no match** ✔

### Entrypoint identification

1. Functions named `main`
2. Functions with a framework decorator (`@app.route`, `@app.get`, `@click.command`, `@task`, …)
3. Module-level code — executes on import
4. **Public functions with no inbound call edge** — either dead code or an
   externally-invoked API. Assuming the latter can only *widen* reachability,
   never hide a real path, which is the safe direction (G2).

Test directories are excluded from the graph: a vulnerable symbol called only
from tests is not reachable in production.

## 3.5 Risk fusion model

```
risk = CVSS
     × reachability_weight   0.1 – 1.0
     × exposure_factor       0.95 local | 1.15 network-reachable
     × dependency_factor     1.10 direct | 0.90 transitive | 0.80 depth ≥ 2
     × fix_factor            1.05 patch available | 0.85 none
     × exploit_factor        1.00 | 1.30 known exploitation
                             clamped to [0, 10]
```

**Why multiplicative rather than additive:** reachability must be able to
*dominate* severity. Under addition, a CVSS 9.8 unreachable finding would still
outrank a CVSS 5.0 reachable one. Multiplication makes 9.8 × 0.1 = 0.98 fall
below 5.0 × 1.0 = 5.0, which is the intended ordering. This is asserted as a
test (`test_reachability_dominates_severity`), not merely intended.

**Why the output stays on the 0–10 scale:** reviewers read CVSS fluently.
Inventing a new scale would add cognitive load for no benefit.

**Why a patch *raises* the score:** counter-intuitive but correct for
prioritisation — an available fix means the finding is *actionable today*. An
unfixable finding needs mitigation planning, a different workflow.

**Actionability threshold: risk ≥ 4.0** *and* reachability ∈ {REACHABLE,
POTENTIALLY_REACHABLE}. Chosen to align with the CVSS MEDIUM boundary. §5.4 of
`docs/05` reports its cost honestly: it is the sole source of the recall loss.

## 3.6 Threat model

Threats to **DepSentry itself**, since a security tool is part of the attack
surface.

| # | Threat | Control | Where |
|---|---|---|---|
| T1 | Tampered SBOM presented as genuine | Ed25519 detached signature, HMAC fallback; canonical serialisation | `integrity.py::sign_sbom` |
| T2 | Scan history edited to hide a past finding | Append-only SHA-256 hash chain; any edit breaks all later links | `integrity.py::AuditLog` |
| T3 | Path traversal via the API scan endpoint | `_safe_path()` resolves and confines to `ALLOWED_ROOT`; 403 otherwise | `api/main.py` |
| T4 | SQL injection into the advisory store | Parameterised queries exclusively; no string interpolation | `vulndb.py` |
| T5 | Malicious project source executing during analysis | **Static analysis only** — `ast.parse`, never `import`, never `exec` | `callgraph.py` |
| T6 | Timing attack on signature comparison | `hmac.compare_digest` | `integrity.py::hmac_verify` |
| T7 | Malformed source crashing the scan | Parse errors collected into `parse_errors`, analysis continues | `callgraph.py::build_call_graph` |

T5 deserves emphasis: the tool analyses untrusted code. Importing it to inspect
it would execute it. Everything is done on the AST.

## 3.6b Live-data extensions (v1.1)

Five capabilities added after the initial evaluation. Every one is **opt-in and
degrades to the v1.0 behaviour** — the default `scan` still makes no network
call and touches no API key.

| Extension | Module | Design constraint it respects |
|---|---|---|
| Live OSV advisories | `osv_client.py` | Falls back to the local corpus if OSV is unreachable. Symbol provenance recorded per finding (`upstream` / `overlay` / `none`) so a curated guess is never presented as upstream fact. |
| EPSS exploit probability | `epss_client.py` | Multiplier bounded to [0.90, 1.40] so EPSS *modulates* ranking but can never override reachability (G1 would be violated if a probability could resurrect an unreachable finding). |
| OpenVEX generation | `vex.py` | Every `not_affected` statement is backed by a call-graph result, not a human assertion — this is what makes the justification checkable. |
| Call-path locations | `callgraph.py` | Evidence becomes a citation: file and line for every hop, encoded as SARIF `codeFlows`. |
| LLM remediation | `remediation.py` | Static-analysis-only invariant (T5) preserved: source is *read* and confined to the scanned project, never executed. |

### Why EPSS multiplies rather than adds

Same argument as reachability in §3.5, applied one level up. An additive EPSS
bonus would let a high-probability *unreachable* finding outrank a reachable
one, reintroducing exactly the ordering error the project exists to correct.
Bounding the multiplier at 1.40 caps the maximum an unreachable CVSS-10 finding
can reach at 1.40 — still below any reachable mid-severity finding.

### Why the symbol overlay is opt-in

OSV's PyPI advisories carry no symbol data (measured: 0 of 171 — see
`docs/05` §5.5b). Without mitigation, live scanning produces only UNKNOWN
verdicts. The overlay supplies symbols, but attributing a package's dangerous
API surface to an arbitrary advisory on that package is a **guess**. It is
therefore off by default (`--overlay-heuristic`), recorded in `symbol_source`,
and reported in the coverage summary on every live scan. It errs toward
REACHABLE — a false positive — never toward hiding a finding.

## 3.7 Key design decisions

| Decision | Alternatives considered | Why this one |
|---|---|---|
| Static AST analysis | Dynamic tracing; symbolic execution | Dynamic requires running untrusted code and exercising every path; symbolic execution does not scale to a dependency tree |
| Four-state verdict | Binary reachable/unreachable | Binary forces a false claim when the analysis is genuinely uncertain (G2) |
| SQLite advisory store | JSON files; live OSV API | Indexed range queries, offline, single file, zero setup (G3) |
| Exact pins beat installed versions | Always trust the environment | A `==` pin is what deploys; the dev environment is incidental |
| Synthetic benchmark | Scrape real projects | Reachability ground truth is unavailable for real projects; generating it makes labels correct by construction. Cost is stated in §5.5 of `docs/05` |
| Multiplicative fusion | Weighted sum; learned model | Sum cannot let reachability dominate; a learned model needs labelled training data that does not exist |

## 3.8 Module structure

| Module | Lines | Responsibility | Depends on |
|---|---|---|---|
| `models.py` | 260 | Dataclasses, enums, derived properties | stdlib only |
| `sbom.py` | 201 | Dependency resolution, CycloneDX emission | models |
| `vulndb.py` | 240 | Advisory storage, version ranges, OSV import | models |
| `callgraph.py` | 300 | AST parsing, call graph, BFS reachability | stdlib only |
| `reachability.py` | 190 | Verdict decision procedure | callgraph, models |
| `risk.py` | 120 | Score fusion, ranking, rationale | models |
| `integrity.py` | 201 | Signing, hash-chained audit log | models, cryptography (optional) |
| `report.py` | 231 | Markdown, JSON, SARIF rendering | models |
| `pipeline.py` | 100 | Stage orchestration | all of the above |
| `cli.py` | 150 | Argument parsing, exit codes | pipeline, report |

`models.py` and `callgraph.py` are stdlib-only by design, so the analysis core
can be reused without pulling in the web or ML stack.
