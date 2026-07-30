# 2. Subject-wise Contribution Matrix

Satisfies **SOP Annexure-A clause 7** (Mapping of Subjects to the Project) and
**clause 12 item 2**.

> ### ⚠ ACTION REQUIRED
>
> The subject names below are a **representative Sem VII B.Tech Cybersecurity
> set**. They are almost certainly not identical to your school's actual
> syllabus. Before submission:
>
> 1. Replace the subject names in §2 with your real Sem VII subject list.
> 2. Confirm every subject has **at least one deliverable** (clause 7 makes this
>    mandatory, not optional).
> 3. Get the school sub-committee's Skill–NOS–Project Mapping Matrix (clause 7
>    says they prepare it at semester start) and align §3 to their NOS codes.
>
> The mapping *logic* below holds regardless of naming — each row ties a real
> module of this codebase to a subject, so re-labelling is mechanical.

---

## 1. How to read this matrix

Clause 7 requires two things of each project:

- "The contribution of every subject to the project" → column 3
- "At least one project deliverable related to each course" → column 4

A deliverable here means a **specific file or artifact**, not a vague activity.
An evaluator should be able to open the named file and see the subject's
concepts in use.

## 2. Subject → contribution → deliverable

| # | Subject (Sem VII) | How the subject contributes | Deliverable (auditable artifact) |
|---|---|---|---|
| S1 | **Software Security / Secure Coding** | The entire premise: distinguishing an exploitable defect from an inert one, and reasoning about the vulnerable-symbol boundary between application and dependency code | `src/depsentry/reachability.py` — four-state verdict model with evidence |
| S2 | **Cryptography & Network Security** | SBOM tamper-evidence via Ed25519 detached signatures with HMAC-SHA256 fallback; append-only audit log as a SHA-256 hash chain; `compare_digest` for timing-safe verification | `src/depsentry/integrity.py`; `tests/test_core.py::TestIntegrity`, `::TestAuditLog` |
| S3 | **Compiler Design / Program Analysis** | AST parsing, symbol-table construction, import alias resolution, call-graph building, BFS reachability over the graph | `src/depsentry/callgraph.py` — `_ModuleVisitor`, `reachable_external_symbols()` |
| S4 | **Database Management Systems** | Advisory store schema in OSV shape; indexing; parameterised queries throughout; version-range predicates; **in-place schema migration** for new columns; SQLite response cache with a content-derived key | `src/depsentry/vulndb.py` — `_SCHEMA`, `_migrate()`; `remediation.py::_Cache` |
| S5 | **Machine Learning / Data Analytics** | Evaluation methodology: confusion matrix, precision/recall/F1, Mean Average Precision, ablation, prevalence-aware interpretation; **EPSS** exploit-probability fusion as a second empirical signal | `experiments/evaluate.py`; `src/depsentry/epss_client.py`; `risk.py::epss_factor` |
| S6 | **Web Technologies / Web Application Security** | REST service design; **path-traversal defence** on the scan endpoint (`_safe_path` confines scans to an allow-listed root, returns 403 otherwise); Streamlit dashboard; self-contained WASM delivery with no external asset fetch | `api/main.py`; `dashboard/app.py`; traversal test in the API smoke check |
| S7 | **DevSecOps / Cloud Security** | Shift-left integration: SARIF 2.1.0 with `codeFlows`, exit-code gating, unreachable findings demoted to `note`; **OpenVEX 0.2.0** generation for CISA/NTIA/EU-CRA machine-readable exploitability exchange | `report.py::to_sarif`, `_code_flow`; `src/depsentry/vex.py` |
| S8 | **Research Methodology / Project Management** | Falsifiable hypotheses stated in advance; control and ablation conditions; seeded reproducibility; explicit limitations including a negative result | `docs/01_problem_statement.md` §1.7; `docs/05_results_and_discussion.md` §5–6 |
| S10 | **Applied AI / API Integration** | Anthropic Messages API for code-specific remediation: prompt construction from advisory + traced path + real source; response caching; graceful degradation; correct handling of removed sampling parameters and the `refusal` stop reason | `src/depsentry/remediation.py`; `tests/test_remediation.py` |
| S11 | **Network Programming / Web APIs** | Live OSV.dev integration (batch queries, CVSS v3.1 base-score derivation from vectors, TLS trust-store handling); EPSS batched lookups; offline fallback on every path | `src/depsentry/osv_client.py`; `epss_client.py` |
| S9 | **Systems Programming / Computer Graphics** | Rust compiled to `wasm32-unknown-unknown` via the raw C ABI (no wasm-bindgen); 3D force-directed layout, rotation matrices, perspective projection, painter's-algorithm depth sorting; zero-allocation render loop over shared linear memory | `viz/src/lib.rs`; `viz/shell.html`; headless engine test `viz/smoke.mjs` |

**Coverage check:** 11 subjects, 11+ distinct deliverables, no subject without an
artifact. ✔ clause 7 satisfied.

## 3. Skill–NOS–Project Mapping

Clause 7 requires a **Skill–NOS–Project Mapping Matrix**. NOS codes are issued
by the sector skill council (SSC NASSCOM for IT-ITeS); the codes below are
**indicative placeholders**.

> **[FILL]** Replace with the exact NOS codes from your school sub-committee's
> matrix. Do not submit placeholder codes.

| Skill demonstrated | Indicative NOS reference | Project evidence |
|---|---|---|
| Secure software design and threat reasoning | SSC/N0501 (indicative) | `docs/03_design_document.md` §4 threat model |
| Static application security analysis | SSC/N0502 (indicative) | `src/depsentry/callgraph.py`, `reachability.py` |
| Applied cryptography for data integrity | SSC/N0904 (indicative) | `src/depsentry/integrity.py` |
| Database design and secure querying | SSC/N0503 (indicative) | `src/depsentry/vulndb.py` |
| Security automation and CI/CD integration | SSC/N0801 (indicative) | SARIF output, `--fail-on` gate |
| Empirical evaluation and technical reporting | SSC/N9001 (indicative) | `experiments/evaluate.py`, `docs/05` |
| Secure API development | SSC/N0505 (indicative) | `api/main.py` with path-traversal control |
| Documentation and professional communication | SSC/N9002 (indicative) | This documentation set |
| Systems programming and data visualisation | SSC/N0506 (indicative) | `viz/src/lib.rs` Rust/WASM engine |

## 4. Course / Programme Outcome mapping

Supports SOP clause 2 (CO/PO/PSO attainment) and clause 14 (NBA/NAAC
outcome-based education).

### Course Outcomes

| CO | Statement | Evidence |
|---|---|---|
| CO1 | Analyse a real-world security problem and derive a testable problem statement | `docs/01` §1.4, §1.7 |
| CO2 | Apply program-analysis techniques to a security decision | `callgraph.py` + `reachability.py` |
| CO3 | Apply cryptographic primitives to achieve integrity and non-repudiation | `integrity.py` |
| CO4 | Design and evaluate a system against a measurable baseline | `experiments/evaluate.py`, `docs/05` |
| CO5 | Communicate technical findings to a professional audience | `docs/06`, dashboard, SARIF output |

### Programme Outcomes

| PO | Outcome | Where demonstrated |
|---|---|---|
| PO1 | Engineering knowledge | Graph theory, cryptography, databases applied together |
| PO2 | Problem analysis | Alert fatigue traced to its root cause: package-level vs symbol-level matching |
| PO3 | Design/development of solutions | Six-stage pipeline, three interfaces |
| PO4 | Conduct investigations | Labelled benchmark, control condition, ablation study |
| PO5 | Modern tool usage | AST analysis, SQLite, FastAPI, Streamlit, pytest, SARIF, CycloneDX, OpenVEX, Rust/WebAssembly, OSV.dev, EPSS, Anthropic API |
| PO6 | Engineer and society | Reduces security-review burden; keeps suppression decisions auditable |
| PO8 | Ethics | Synthetic data disclosed in five separate places rather than passed off as real CVEs |
| PO9 | Individual and team work | **[FILL]** — `docs/logbook.md` |
| PO10 | Communication | Documentation set, presentation, live demo |
| PO12 | Life-long learning | Limitations section names the specific next steps (§6 of `docs/05`) |

### Programme Specific Outcomes

| PSO | Outcome | Evidence |
|---|---|---|
| PSO1 | Apply cybersecurity principles to secure software systems | Supply chain risk analysis end to end |
| PSO2 | Use security tooling and automation in a professional workflow | CI gate, SARIF, signed SBOM, REST API |
