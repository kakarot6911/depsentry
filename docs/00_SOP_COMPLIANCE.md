# SOP Compliance Traceability Matrix

Maps every requirement in **Annexure-A, Notification 7 (Ref. SSPU/RO/2026-27/2921,
17/07/2026)** to the artifact that satisfies it. Intended as the first page a
reviewer or external evaluator opens.

> **Action required before submission.** Items marked **[FILL]** need details
> only you and your school can supply — team roster, guide name, actual subject
> list, real review dates. Everything else is complete.

---

## Clause 3 — Scope

| Requirement | Status |
|---|---|
| UG/PG student, First to Final Year | Sem VII, B.Tech Cybersecurity |
| Domain-specific course with skill-based credits | Yes |
| Not an IDSC course | Correct — this is a school-domain project |

## Clause 6.1 — Project type for the semester

> **Sem VII → Industry or Research-Oriented Project**

DepSentry is deliberately **both**:

- **Industry**: emits CycloneDX SBOMs and SARIF, has a CI gate with a non-zero
  exit code, and targets a problem (dependency alert fatigue) every software
  organisation has.
- **Research**: states two falsifiable hypotheses, evaluates against a labelled
  benchmark with a control condition and an ablation, and reports limitations
  including a negative one.

## Clause 7 — Subject mapping

| Requirement | Artifact |
|---|---|
| Skill–NOS–Project Mapping Matrix | `docs/02_subject_contribution_matrix.md` |
| Contribution of every subject explained | Same document, column 3 |
| At least one deliverable per course | Same document, column 4 — **[FILL]** confirm against your real subject list |

## Clause 8 — Team formation

| Requirement | Status |
|---|---|
| 3–5 students per group | **[FILL]** `docs/06_final_project_report.md` §1.2 |
| Faculty guide assigned | **[FILL]** |

## Clause 9 — Lifecycle and timeline

| Phase | SOP weeks | Artifact |
|---|---|---|
| 1. Problem identification | 1–2 | `docs/01_problem_statement.md` (includes literature survey) |
| 2. Design and planning | 3–4 | `docs/03_design_document.md` |
| 3. Implementation | 5–6 | `docs/04_implementation_details.md`, `src/` |
| 4. Evaluation and documentation | 7–8 | `docs/05_results_and_discussion.md`, `reports/` |

## Clause 10 — Roles and responsibilities

| Requirement | Artifact |
|---|---|
| Maintain project records and logbooks | `docs/logbook.md` |
| Follow ethical practices, submit original work | `docs/08_appendix.md` §A4, and the synthetic-data disclosure below |

## Clause 11 — Assessment

| Component | Weight | Where the evidence lives |
|---|---|---|
| Progress Review 1 | 25% | `docs/review_tracker.md` — Phase 1–2 artifacts |
| Progress Review 2 | 25% | `docs/review_tracker.md` — Phase 3 artifacts |
| Progress Review 3 | 25% | `docs/review_tracker.md` — Phase 4 artifacts |
| End-term examination | 25% | Breakdown below |

End-term sub-components (clause 11.2 B):

| Sub-component | Weight | Artifact |
|---|---|---|
| Problem Definition & Literature Review | 5 | `docs/01_problem_statement.md` |
| Implementation & Results | 7.5 | `src/`, `docs/04`, `docs/05` |
| Subject Integration | 5 | `docs/02_subject_contribution_matrix.md` |
| Report & Presentation | 5 | `docs/06_final_project_report.md` |
| Teamwork & Professional Ethics | 2.5 | `docs/logbook.md`, `docs/08_appendix.md` §A4 |

Clause 11.1 requires an **industry expert or external evaluator at the final
assessment**, and submission of the final report to the school office through
the project guide. **[FILL]** — arrange with your guide; note the date in
`docs/review_tracker.md`.

## Clause 12 — Documentation requirements

All eight mandated documents are present:

| # | SOP requirement | File |
|---|---|---|
| 1 | Problem Statement and Objectives | `docs/01_problem_statement.md` |
| 2 | Subject-wise Contribution Matrix | `docs/02_subject_contribution_matrix.md` |
| 3 | Design Documents | `docs/03_design_document.md` |
| 4 | Implementation Details | `docs/04_implementation_details.md` |
| 5 | Results and Discussion | `docs/05_results_and_discussion.md` |
| 6 | Final Project Report | `docs/06_final_project_report.md` |
| 7 | Source Code / Models / Prototype | `src/`, `api/`, `dashboard/`, guide in `docs/07_source_code_guide.md` |
| 8 | Appendix | `docs/08_appendix.md` |

## Clause 13 — Academic integrity

| Requirement | Status |
|---|---|
| Plagiarism below 15% | Prose is original. Run your institutional check before submission. |
| Proper citations and references | `docs/08_appendix.md` §A3 |
| No fabrication or falsification of results | **Every number in `docs/05` is machine-generated** by `experiments/evaluate.py` into `reports/evaluation.json`, reproducible from seed 42. Nothing is hand-entered. |

**Synthetic data disclosure (stated here, in `docs/05`, in `docs/08`, in the
dashboard UI, and in the seeder's own docstring):** the advisory corpus uses
`DEPS-` identifiers, not `CVE-` identifiers. The advisories are modelled on the
structure and severity distribution of real OSV records but are **not claims
about real defects in the named packages**. The benchmark projects are likewise
generated. This is disclosed rather than buried because presenting synthetic
advisories as real CVEs would be exactly the falsification clause 13 prohibits.

## Clause 14 — Expected outcomes

| Outcome | Evidence |
|---|---|
| Higher-level thinking and problem-solving | Reachability reframes a matching problem as a graph-traversal problem |
| Industry readiness and practical exposure | SARIF + CycloneDX + CI exit codes are the real interchange formats |
| Innovation, leadership, teamwork | **[FILL]** — record division of work in `docs/logbook.md` |
| NBA/NAAC outcome-based education | CO/PO/PSO mapping in `docs/02_subject_contribution_matrix.md` §4 |
