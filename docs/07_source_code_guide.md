# 7. Source Code / Models / Prototype Guide

SOP clause 12 item 7.

---

## 7.1 Repository layout

```
depsentry/
├── README.md                     Quick start
├── requirements.txt              Dependencies
├── run.sh                        One-command driver
├── LICENSE                       MIT
│
├── src/depsentry/                Analysis core (importable library)
│   ├── models.py                 Dataclasses, enums, derived properties
│   ├── sbom.py                   Dependency resolution → CycloneDX
│   ├── vulndb.py                 SQLite advisory store, version ranges
│   ├── callgraph.py              AST parsing → call graph → BFS
│   ├── reachability.py           Verdict decision procedure
│   ├── risk.py                   Score fusion and ranking
│   ├── integrity.py              Signing, hash-chained audit log
│   ├── report.py                 Markdown / JSON / SARIF rendering
│   ├── pipeline.py               Stage orchestration
│   └── cli.py                    Command line interface
│
├── data/
│   ├── seed_vulndb.py            Build the advisory corpus
│   ├── make_benchmark.py         Generate the labelled benchmark
│   └── vulndb.sqlite3            Advisory store (generated)
│
├── benchmark/                    40 generated projects (generated)
│   └── ground_truth.json         Labels
│
├── experiments/
│   └── evaluate.py               Research evaluation harness
│
├── viz/                          Rust 3D engine, compiled to WebAssembly
│   ├── Cargo.toml
│   ├── src/lib.rs                Force layout, camera, projection, depth sort
│   ├── shell.html                Canvas renderer + HUD (JS rasterises only)
│   ├── smoke.mjs                 Headless engine test (node)
│   └── target/.../depsentry_viz.wasm   29 KB build artifact
│
├── examples/showcase_app/        Deliberately vulnerable demo fixture
│
├── api/main.py                   FastAPI service
├── dashboard/app.py              Streamlit dashboard (4 tabs, incl. 3D)
│
├── tests/                        56 tests
│   ├── conftest.py               Project-tree fixtures
│   ├── test_reachability.py      Core claim
│   └── test_core.py              Everything else
│
├── reports/                      Generated output
│   ├── evaluation.json / .md     Research results
│   └── audit.jsonl               Hash-chained scan log
│
└── docs/                         SOP clause 12 documents 1–8
```

## 7.2 Reading order

For an evaluator with limited time, read in this order:

| Order | File | Why |
|---|---|---|
| 1 | `src/depsentry/reachability.py` | The core contribution — 190 lines, the whole idea |
| 2 | `tests/test_reachability.py` | The claim as executable assertions |
| 3 | `src/depsentry/callgraph.py` | How the graph is built |
| 4 | `src/depsentry/risk.py` | Why reachability dominates severity |
| 5 | `experiments/evaluate.py` | How the numbers are produced |
| 6 | `src/depsentry/integrity.py` | Cryptographic controls |

Start at `reachability.py::ReachabilityAnalyzer.analyze` — that method *is* the
project.

## 7.3 Setup

```bash
cd ~/depsentry
python3 -m pip install -r requirements.txt
./run.sh setup            # seed advisory DB + generate benchmark
./run.sh test             # 56 tests
```

Python 3.11+ required (`tomllib`). Developed on 3.14.

## 7.4 Running

```bash
./run.sh setup            # seed DB, generate benchmark
./run.sh test             # pytest + headless wasm engine test
./run.sh demo             # motivating example: safe vs unsafe
./run.sh evaluate         # research evaluation
./run.sh scan <path>      # scan any Python project
./run.sh build-viz        # compile the Rust engine to wasm
./run.sh viz [path]       # 3D attack surface (default: showcase_app)
./run.sh dashboard        # Streamlit UI (loopback; --network to expose)
./run.sh api              # FastAPI on :8000 (loopback; --network to expose)
./run.sh all              # setup + test + evaluate
```

### Building the Rust engine

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
./run.sh build-viz
```

The wasm artifact is committed-optional: if it is missing, `./run.sh viz` builds
it, and the dashboard's 3D tab shows a build instruction instead of failing. The
rest of DepSentry has no dependency on Rust.

### CLI directly

```bash
export PYTHONPATH=src

python3 -m depsentry.cli db-info
python3 -m depsentry.cli sbom ./myproject --out sbom.json
python3 -m depsentry.cli scan ./myproject --out reports --fail-on 7.0
python3 -m depsentry.cli scan ./myproject --sign key.pem
python3 -m depsentry.cli verify-log
```

Exit codes: `0` pass, `1` gate breached, `2` bad input.

### Library

```python
import sys; sys.path.insert(0, "src")
from depsentry.pipeline import scan_project

result = scan_project("./myproject")
print(f"{len(result.actionable_findings)} actionable of {len(result.findings)}")
print(f"noise reduction: {result.noise_reduction():.1%}")

for f in result.actionable_findings:
    print(f"#{f.rank} {f.vulnerability.vuln_id} risk={f.risk_score:.2f}")
    for path in f.call_paths:
        print("   ", path.render())
```

### REST API

```bash
uvicorn api.main:app --reload --port 8000
# docs at http://127.0.0.1:8000/docs

curl -X POST localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"project_path":"benchmark/project_001","fail_on":7.0}'
```

## 7.5 CI integration

GitHub Actions:

```yaml
- name: DepSentry supply chain scan
  run: |
    export PYTHONPATH=src
    python3 -m depsentry.cli scan . --out reports --fail-on 7.0

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: reports/*.sarif
```

Unreachable findings are emitted at SARIF level `note`, so they appear in the
security tab without breaking the build.

## 7.6 Extending

| To do this | Change this |
|---|---|
| Use real OSV data | `VulnerabilityDB.import_osv()` — no other change needed |
| Add a distribution→import alias | `_IMPORT_ALIASES` in `reachability.py` |
| Recognise a new framework's entrypoints | `_ENTRYPOINT_DECORATORS` in `callgraph.py` |
| Adjust risk weights | Module-level constants in `risk.py` |
| Change the action threshold | `ACTIONABLE_THRESHOLD` in `risk.py`; also `Finding.actionable` |
| Add an output format | New function in `report.py`, wire into `write_reports()` |
| Support another language | New `callgraph` implementation returning the same `CallGraph` |

## 7.7 Reproducing the published results

```bash
python3 data/seed_vulndb.py       # 30 advisories
python3 data/make_benchmark.py    # 40 projects, seed 42
python3 experiments/evaluate.py   # → reports/evaluation.{json,md}
```

Deterministic. Any run on the same seed reproduces every figure in
`docs/05_results_and_discussion.md` exactly.

## 7.8 Code statistics

| Component | Files | Lines |
|---|---|---|
| Analysis core (`src/depsentry/`) | 10 | ~1,900 |
| Interfaces (`api/`, `dashboard/`) | 2 | ~400 |
| Data generation (`data/`) | 2 | ~450 |
| Evaluation (`experiments/`) | 1 | ~300 |
| Tests (`tests/`) | 3 | ~650 |
| **Total Python** | **19** | **3,715** |
| Documentation (`docs/`) | 11 | — |

Tests: 56, all passing, ~0.3 s.
