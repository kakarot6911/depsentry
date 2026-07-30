# Review Tracker

Satisfies **SOP clause 11.3** (Review System) and **clause 7.1 / 4** (review
committee monitors progress **every 15 days**).

> **[FILL] all date columns.** The week structure below follows the SOP's
> 8-week lifecycle (clause 9); anchor Week 1 to your actual semester start and
> the rest follow.

---

## Assessment weighting (clause 11.2)

| Component | Weight |
|---|---|
| Progress Review 1 | 25% |
| Progress Review 2 | 25% |
| Progress Review 3 | 25% |
| End-Term Examination | 25% |
| **Total** | **100%** (scaled down to 15 marks per clause 11.2 note) |

---

## Progress Review 1 — Weeks 1–2 (Problem Identification)

**Date: [FILL]  ·  Committee: [FILL]  ·  Marks: __ / 25**

Maps to SOP Phase 1: identify a real-world problem, conduct a literature survey,
map subject-wise concepts, finalise and obtain approval for the problem statement.

| Deliverable | Artifact | Status |
|---|---|---|
| Real-world problem identified | `01_problem_statement.md` §1.2 | ✅ Complete |
| Literature / background survey | `01_problem_statement.md` §1.3 (7 areas, 22 references) | ✅ Complete |
| Subject-wise concept mapping | `02_subject_contribution_matrix.md` | ✅ Complete — **[FILL] real subject names** |
| Problem statement finalised | `01_problem_statement.md` §1.4 | ✅ Complete |
| Objectives defined | §1.6 — 8 objectives, each with a verifiable outcome | ✅ Complete |
| Hypotheses stated **in advance** | §1.7 — H1, H2 | ✅ Complete |
| Guide approval of problem statement | — | ⬜ **[FILL]** |

**Talking points:** the PyYAML `safe_load` example makes the problem concrete in
30 seconds. Lead with it.

**Guide's remarks:** ______________________________________________

---

## Progress Review 2 — Weeks 3–6 (Design + Implementation)

**Date: [FILL]  ·  Committee: [FILL]  ·  Marks: __ / 25**

Maps to SOP Phase 2 (system architecture, algorithms, tool selection) and
Phase 3 (coding, testing, iteration).

| Deliverable | Artifact | Status |
|---|---|---|
| System architecture | `03_design_document.md` §3.2 — 6-stage pipeline | ✅ Complete |
| Data model | §3.3 | ✅ Complete |
| Core algorithm specified | §3.4 — five-rule decision procedure | ✅ Complete |
| Risk model justified | §3.5 — why multiplicative, not additive | ✅ Complete |
| Threat model | §3.6 — 7 threats to the tool itself, each with a control | ✅ Complete |
| Tool/technology selection | `04_implementation_details.md` §4.1 | ✅ Complete |
| Working implementation | `src/depsentry/` — 10 modules, ~1,900 lines | ✅ Complete |
| Testing | 56 tests, all passing | ✅ Complete |
| Interfaces | CLI + REST API + dashboard | ✅ Complete |
| Iteration on feedback | `04` §4.10 — 6 problems found and fixed | ✅ Complete |

**Demo for this review:**

```bash
./run.sh test        # 56 passing
./run.sh demo        # safe vs unsafe, live
```

**Talking points:** two bugs were found *by tests, not by inspection* — the
exact-pin precedence bug and the pre-release ordering bug. Both are documented
in the logbook. That is the point of the test suite and worth saying out loud.

**Guide's remarks:** ______________________________________________

---

## Progress Review 3 — Weeks 7–8 (Evaluation and Documentation)

**Date: [FILL]  ·  Committee: [FILL]  ·  Marks: __ / 25**

Maps to SOP Phase 4: analyse results, prepare the final report, present and
demonstrate.

| Deliverable | Artifact | Status |
|---|---|---|
| Results analysed | `05_results_and_discussion.md` | ✅ Complete |
| Both hypotheses tested | §5.2 (H1), §5.3 (H2) — both supported | ✅ Complete |
| Control condition | §5.1 — CVSS ≥ 7 gate + no-triage | ✅ Complete |
| Ablation study | §5.4 — revealed a weakness in our own design | ✅ Complete |
| Threats to validity | §5.6 — construct, internal, external, statistical | ✅ Complete |
| Future work | §5.9 — 7 items, ordered by value | ✅ Complete |
| Final project report | `06_final_project_report.md` | ✅ Complete — **[FILL] title page** |
| All 8 clause-12 documents | `docs/` | ✅ Complete |
| Presentation | — | ⬜ **[FILL]** build slides from `06` §3 |
| Demonstration rehearsed | `06` §3 — 10-minute script | ⬜ **[FILL]** |

**Headline numbers to have memorised:**

- Alert volume 107 → 80 (**25.2%** reduction vs the CVSS gate)
- Precision **0.318 → 1.000**
- MAP **0.512 → 0.950**
- **Two thirds** of matched advisories were unreachable

**Guide's remarks:** ______________________________________________

---

## End-Term Examination (25%)

**Date: [FILL]  ·  External / industry evaluator: [FILL]  ·  Marks: __ / 25**

Clause 11.1: participation of an industry expert or external evaluator is
**compulsory**, and the final report must be submitted to the school office
**through the project guide**.

| Sub-component (clause 11.2 B) | Weight | Marks | Primary artifact |
|---|---|---|---|
| Problem Definition & Literature Review | 5 | __ | `01_problem_statement.md` |
| Implementation & Results | 7.5 | __ | `src/`, `04`, `05` |
| Subject Integration | 5 | __ | `02_subject_contribution_matrix.md` |
| Report & Presentation | 5 | __ | `06_final_project_report.md` |
| Teamwork & Professional Ethics | 2.5 | __ | `logbook.md`, `08` §A4 |
| **Total** | **25** | __ | |

**Absence policy (clause 11.2, PBL Policy Statement).** If a student is absent
for the PBL examination, viva, or presentation, review marks are still counted;
≥40% (minimum 6/15) is a Pass, otherwise Fail with reappearance in the next
examination on payment of the prescribed fee.

---

## Fortnightly progress log (clause 4 / 7.1 — every 15 days)

| # | Date | Phase | Progress | Blockers | Next |
|---|---|---|---|---|---|
| 1 | [FILL] | Problem ID | Problem statement, literature survey, objectives, hypotheses | — | Architecture |
| 2 | [FILL] | Design | Architecture, data model, decision procedure, threat model | — | Core implementation |
| 3 | [FILL] | Implementation | SBOM, advisory DB, call graph, reachability | Pin-precedence bug | Risk fusion, integrity |
| 4 | [FILL] | Implementation | Risk fusion, signing, audit log, CLI/API/dashboard | Pre-release ordering bug | Benchmark |
| 5 | [FILL] | Evaluation | Benchmark corpus, evaluation harness, ablation | — | Documentation |
| 6 | [FILL] | Documentation | All clause-12 documents, demo script | — | Final review |

**Committee signatures:** ______________________________________________
