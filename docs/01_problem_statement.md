# 1. Problem Statement and Objectives

**Project:** DepSentry — Reachability-Aware Software Supply Chain Risk Analyzer
**Semester:** VII (Industry / Research-Oriented Project, per SOP clause 6.1)
**Programme:** B.Tech Cybersecurity, Symbiosis Skills & Professional University, Pune
**Academic Year:** 2026–27

---

## 1.1 Background

Modern applications are assembled, not written. A typical Python service
declares perhaps 15 direct dependencies and inherits several hundred transitive
ones. Every one of those packages is code the organisation ships but did not
write, review, or test.

The industry response has been the Software Bill of Materials (SBOM) plus
automated dependency scanning. A scanner reads the dependency list, matches each
package version against an advisory database (OSV, NVD, GitHub Advisory), and
reports every match.

This works. It works so well that it has created a second problem.

## 1.2 The problem

**Dependency scanners match packages, but vulnerabilities live in functions.**

A scanner reports a finding when a vulnerable *package version* is installed. It
does not ask whether the *vulnerable function inside that package* is ever
called. Those are very different questions, and the gap between them is where
the alert fatigue comes from.

A concrete instance, drawn from this project's own test suite:

> An application depends on PyYAML 5.4.1. An advisory reports arbitrary code
> execution, CVSS 9.8, in `yaml.load()`. Every conventional scanner raises a
> CRITICAL and fails the build.
>
> The application only ever calls `yaml.safe_load()`. The vulnerable function
> is never invoked. The finding is real, correctly matched, and operationally
> meaningless.

Three consequences follow:

1. **Alert fatigue.** Developers face queues of criticals where most are
   unreachable. The rational response — ignore the queue — is also the one that
   causes the genuinely exploitable finding to be missed.
2. **Misallocated remediation.** Effort goes to whichever finding has the
   highest CVSS, not the one an attacker could actually reach.
3. **Broken CI gates.** A `fail-on-critical` rule blocks releases over
   unreachable code, so teams disable the gate, losing the control entirely.

The severity number itself is part of the problem. CVSS scores the
vulnerability *in the abstract*: it deliberately excludes how the component is
used in your system. Using it as a priority ordering treats an unreachable RCE
as more urgent than a directly-invoked medium-severity flaw.

## 1.3 Literature and tooling survey

*(SOP clause 9, Phase 1: literature survey / background study.)*

| Area | Representative work | What it does | Gap DepSentry addresses |
|---|---|---|---|
| SBOM standards | CycloneDX, SPDX | Standardise component inventory interchange | Inventory only; says nothing about usage |
| Advisory databases | OSV, NVD, GitHub Advisory | Machine-readable advisories with affected version ranges | Version-range matching only; symbol data present but largely unused by consumers |
| Dependency scanners | `pip-audit`, Dependabot, Trivy, Snyk Open Source | Match SBOM against advisories, propose upgrades | Report on package presence, not function reachability |
| Reachability analysis | Commercial "reachability" tiers in some SCA products | Narrow findings using call-graph analysis | Proprietary, closed methodology, not independently reproducible or auditable |
| Static call graphs | `pycg`, `pyan`, Soot/WALA (JVM) | Construct call graphs for a language | General-purpose; not joined to advisory symbol data |
| Risk frameworks | CVSS v3.1, EPSS, CISA KEV | Score severity, exploit probability, known exploitation | Context-free with respect to *this* codebase |
| Vulnerability exchange | VEX / CSAF | Lets a vendor *assert* "not affected" | Assertion is manual; DepSentry derives it as evidence |

**The gap.** SBOM tooling knows *what* you depend on. Advisory databases know
*what is wrong* with it — and OSV records frequently name the affected symbol.
Call-graph tooling knows *what your code calls*. No open, reproducible pipeline
joins all three. Commercial products that do keep the method closed, which makes
their suppressions unauditable — a serious problem when suppression is a
security decision.

DepSentry closes that gap with an open, reproducible implementation, and — the
part that matters for a research project — *measures* whether doing so helps.

## 1.4 Problem statement

> Conventional dependency scanners report vulnerabilities based on package
> version matching alone. This produces a high volume of findings whose
> vulnerable code paths are never executed, causing alert fatigue and
> misallocated remediation effort. **There is no open, reproducible method that
> joins SBOM inventory, advisory symbol data, and static call-graph reachability
> to distinguish exploitable dependency vulnerabilities from inert ones, and no
> published measurement of how much such a method actually reduces analyst
> workload.**

## 1.5 Aim

To design, implement, and empirically evaluate an open-source analyzer that
prioritises dependency vulnerabilities by **static reachability of the
vulnerable symbol from application entrypoints**, and to quantify the reduction
in review volume achieved without loss of genuinely exploitable findings.

## 1.6 Objectives

| # | Objective | Verifiable outcome |
|---|---|---|
| O1 | Generate a CycloneDX SBOM resolving direct and transitive dependencies | `src/depsentry/sbom.py`; valid CycloneDX 1.5 output |
| O2 | Maintain an offline advisory store in OSV schema with symbol-level data | `src/depsentry/vulndb.py`; 30-advisory corpus, 100% symbol coverage |
| O3 | Construct an import-aware static call graph of the application | `src/depsentry/callgraph.py`; entrypoint detection + path extraction |
| O4 | Classify each finding REACHABLE / POTENTIALLY_REACHABLE / UNREACHABLE / UNKNOWN with a call path as evidence | `src/depsentry/reachability.py`; every REACHABLE verdict carries a path |
| O5 | Fuse severity with reachability, exposure, dependency depth, and exploit status into one ranked score | `src/depsentry/risk.py` |
| O6 | Guarantee SBOM and audit-log integrity cryptographically | `src/depsentry/integrity.py`; Ed25519/HMAC signing, hash-chained log |
| O7 | Evaluate against a labelled benchmark versus a CVSS-gate control | `experiments/evaluate.py`; `reports/evaluation.md` |
| O8 | Deliver CI-usable interfaces: CLI exit codes, SARIF, REST API, dashboard | `cli.py`, `report.py`, `api/`, `dashboard/` |

## 1.7 Hypotheses

Stated before the experiment was run, and reported in `docs/05` whether or not
they held.

- **H1 (volume).** Reachability-aware filtering reduces the number of findings
  requiring developer review, relative to a CVSS ≥ 7.0 gate, *without* reducing
  recall of genuinely exploitable findings.
- **H2 (ranking).** Reachability-aware ranking achieves higher Mean Average
  Precision than CVSS-only ordering.

## 1.8 Scope

**In scope:** Python (PyPI) applications; static intraprocedural call-graph
analysis with import resolution; offline advisory matching; CycloneDX SBOM;
SARIF output; CLI, REST, and dashboard interfaces; reproducible evaluation.

**Out of scope:** languages other than Python; dynamic/runtime instrumentation;
automated patching or PR generation; live network fetches from advisory feeds
(the importer exists, but the corpus ships offline); container and OS-package
scanning; full PEP 440 version specifier semantics.

## 1.9 Deliverables

1. Working analyzer — CLI, REST API, Streamlit dashboard
2. Offline advisory database with symbol-level records
3. Labelled 40-project benchmark corpus, deterministic from a seed
4. Reproducible evaluation harness with control and ablation conditions
5. 56-test automated suite
6. This documentation set (SOP clause 12, items 1–8)
