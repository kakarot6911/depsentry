# 4. Implementation Details

SOP clause 9 Phase 3 (Implementation) and clause 12 item 4.

---

## 4.1 Technology stack

| Layer | Technology | Why |
|---|---|---|
| Language | Python 3.11+ (developed on 3.14) | `ast` module gives first-class access to the syntax tree of the language being analysed |
| Static analysis | `ast` (stdlib) | No third-party parser needed; guaranteed to match the interpreter's grammar |
| Storage | SQLite (stdlib `sqlite3`) | Indexed queries, single-file, offline, zero configuration |
| Cryptography | `cryptography` (Ed25519), `hmac`/`hashlib` fallback | Real public-key signatures where available; degrades gracefully |
| Config parsing | `tomllib` (stdlib 3.11+) | PEP 621 `pyproject.toml` support without a dependency |
| API | FastAPI + Pydantic | Automatic OpenAPI docs; request validation at the boundary |
| Dashboard | Streamlit | Fastest path to an interactive demo for the external evaluator |
| Testing | pytest | Fixtures make throwaway project trees trivial |
| Analysis | pandas | Benchmark result tabulation |

## 4.2 Stage 1 — SBOM generation (`sbom.py`)

Resolution is breadth-first over `importlib.metadata`:

1. Parse `requirements.txt` and `pyproject.toml` → direct dependencies, **with
   the comparison operator retained**.
2. For each direct dependency, choose the version:
   - exact `==` pin → **the pin wins** (it is what deploys)
   - otherwise → the installed version
   - otherwise → the declared range text
3. Walk `dist.requires` transitively to `max_depth=4`, marking each package with
   its parent chain.

Two subtleties worth noting:

- **Extras are excluded.** Requirements guarded by `extra == "..."` are not
  installed by default, so including them would inflate the SBOM with packages
  that are not present.
- **RECORD fingerprinting.** Each distribution's `RECORD` file is SHA-256
  hashed as an offline tamper-evidence anchor. A production deployment would
  compare wheel digests against the index; RECORD is the closest equivalent
  available with no network.

The exact-pin rule was a **bug fix discovered during benchmarking**: the first
implementation always preferred the installed version, so benchmark projects
pinning `requests==2.28.0` were scanned as the locally installed 2.32.x and
matched no advisories. Recorded in `docs/logbook.md`.

## 4.3 Stage 2 — Advisory matching (`vulndb.py`)

Schema follows the OSV `affected.ranges` model: `(introduced, fixed]` half-open
intervals, `fixed = NULL` meaning unbounded.

The version comparator is the part that required the most care. It returns a
three-part tuple:

```python
(release_quad, is_final, prerelease_tokens)
# "1.0.0"    → ((1,0,0,0), 1, ())
# "1.0.0a1"  → ((1,0,0,0), 0, (('a',), (1,)))
```

The `is_final` flag exists because naive token-tuple comparison makes `1.0.0a1`
the *longer* tuple and therefore the *greater* one — exactly backwards. That
would place pre-release users outside a range that genuinely affects them.
**This was caught by a failing test, not by inspection**
(`test_prerelease_sorts_below_release`); see `docs/logbook.md`.

The release tuple is padded to four components so `1.0` and `1.0.0` compare
equal. Local version identifiers (`1.2.3+local`) are stripped.

An unpinned dependency (`*`) matches every range — the conservative reading,
since it could resolve into the vulnerable window.

## 4.4 Stage 3 — Call graph construction (`callgraph.py`)

`_ModuleVisitor` subclasses `ast.NodeVisitor` and does four things per module:

**Import table.** `visit_Import` and `visit_ImportFrom` build
`{local_alias: fully_qualified_name}`. `import numpy as np` → `{"np": "numpy"}`;
`from yaml import load` → `{"load": "yaml.load"}`. Relative imports resolve
against the module's own package path.

**Function registry.** Each `FunctionDef`/`AsyncFunctionDef` becomes a
`FunctionNode` keyed by dotted qualname, with class nesting preserved via a
scope stack.

**Call resolution.** `visit_Call` flattens the call target to a dotted name,
splits the head, and looks it up in the import table. Resolved external calls go
into `graph.external_calls`; internal ones become graph edges. Chained calls
(`foo().bar()`) descend to the base receiver.

**Dynamic dispatch detection.** Calls to `getattr`, `eval`, `exec`,
`__import__`, `globals`, `vars` set `uses_dynamic_dispatch` on the enclosing
function instead of creating an edge. This flag is what later produces
POTENTIALLY_REACHABLE rather than a false UNREACHABLE.

Module-level calls attach to a synthetic `module:<module>` node marked as an
entrypoint, since import-time code always executes.

`reachable_external_symbols()` then runs BFS from every entrypoint (default
`max_hops=12`), recording for each external symbol the entrypoint and
intermediate steps that reach it — the evidence shown to the developer.

Robustness: unparseable files are recorded in `parse_errors` and skipped, never
raised. One malformed file must not abort the scan.

## 4.5 Stage 4 — Reachability verdicts (`reachability.py`)

Implements the five-rule procedure from `docs/03` §3.4.

The distribution-name-to-import-name problem is handled by `import_names_for()`:
PyPI names and import names frequently differ (`pyyaml` → `yaml`, `pillow` →
`PIL`, `scikit-learn` → `sklearn`). Without this mapping every PyYAML advisory
would be silently classified UNREACHABLE — a false-negative failure mode, the
dangerous direction. Covered by `TestImportAliases`.

Symbol matching (`_matching_symbols`) applies the three positive rules from
§3.4. The `yaml.safe_load` / `yaml.load` discrimination is asserted directly in
`test_safe_loader_does_not_match_unsafe_advisory`.

Call paths are sorted shortest-first and capped at five per finding — a reviewer
needs one convincing path, not forty.

## 4.6 Stage 5 — Risk fusion (`risk.py`)

Six bounded multipliers, clamped to `[0, 10]`. All constants are module-level
named values, not inline literals, so an evaluator can see and challenge them.

`explain()` generates the rationale list attached to every finding. This is a
requirement, not a nicety: G1 says an unexplained suppression is untrustworthy.

## 4.7 Stage 6 — Integrity (`integrity.py`)

**SBOM signing.** Ed25519 detached signatures when `cryptography` is available,
HMAC-SHA256 otherwise, so the tool still functions with no key infrastructure.
Signature format is `algorithm:hex`, self-describing for verification. The
payload is `SBOM.canonical_bytes()` — sorted keys, no whitespace, timestamp
excluded.

**Audit log.** Append-only JSONL where each entry's digest is
`SHA256(prev_hash ‖ canonical_json(body))`. Editing or deleting any historical
entry breaks verification of everything after it. Both attacks are covered by
tests (`test_tampering_is_detected`, `test_deletion_is_detected`).

Private keys are written mode `0600`.

## 4.8 Interfaces

**CLI** (`cli.py`) — `scan`, `sbom`, `verify-log`, `db-info`.

```bash
depsentry scan ./myapp --out reports --sign key.pem --fail-on 7.0
```

`--fail-on` is the CI contract: exit 1 when an *actionable* finding reaches the
threshold, 0 otherwise. Unreachable findings never break a build.

**REST API** (`api/main.py`) — `/health`, `/advisories`, `/scan`, `/scan/sarif`,
`/sbom`, `/audit/verify`. Every path-taking endpoint goes through `_safe_path()`
(threat T3). Auto-generated OpenAPI docs at `/docs`.

**Dashboard** (`dashboard/app.py`) — three tabs: Scan (metrics, findings table,
per-finding call-path evidence, suppression audit trail), Benchmark results, and
Advisory corpus.

**Report formats** (`report.py`) — Markdown for humans, JSON for machines,
SARIF 2.1.0 for CI, CycloneDX for SBOM interchange. In SARIF, non-actionable
findings are emitted at level `note`: visible in the dashboard, never
build-breaking.

## 4.9 Testing

56 tests, all passing, ~0.3 s.

| Group | Count | Focus |
|---|---|---|
| `TestSymbolDiscrimination` | 3 | The `safe_load`/`load` distinction — the core claim |
| `TestVerdictRules` | 4 | All five decision rules including fail-safe behaviour |
| `TestCallGraph` | 6 | Decorators, chains, aliases, `from` imports, syntax errors, test exclusion |
| `TestImportAliases` | 2 | Distribution → module name mapping |
| `TestVersionRanges` | 9 | Boundaries, pre-releases, local versions, unpinned |
| `TestSBOM` | 4 | Pin precedence, parsing, CycloneDX shape, canonicalisation |
| `TestAdvisoryMatching` | 2 | Range join, OSV import |
| `TestRiskFusion` | 4 | Reachability dominance, clamping, ranking |
| `TestIntegrity` | 5 | Sign/verify, wrong key, tampering, unsigned |
| `TestAuditLog` | 4 | Chain verification, edit detection, deletion detection |
| `TestPipeline` | 5 | End-to-end on safe and unsafe projects |
| `TestReporting` | 3 | Markdown, SARIF well-formedness, note downgrade |
| `TestSeverity` | 5 | CVSS band boundaries |

Fixtures build real project trees on `tmp_path`, so the pipeline is exercised
against actual files rather than mocks.

## 4.10 Implementation problems and resolutions

| Problem | Symptom | Resolution |
|---|---|---|
| Installed version overrode exact pins | Benchmark projects matched almost no advisories | Retain the operator during parsing; `==` wins over the environment |
| Pre-release versions sorted above releases | `1.0.0a1` compared greater than `1.0.0` | Three-part comparison tuple with an explicit `is_final` flag |
| PyPI name ≠ import name | Every PyYAML/Pillow advisory would read UNREACHABLE | `_IMPORT_ALIASES` map plus `import_names_for()` |
| Chained calls unresolved | `foo().bar()` produced no edge | Descend through `ast.Call` to the base receiver |
| Test code inflating reachability | Symbols used only in tests looked production-reachable | Exclude test directories from the graph |
| `dist.metadata["License"]` deprecation | 16 warnings on every run | `_license_of()` using `.get()` |

Each of these is dated in `docs/logbook.md`.
