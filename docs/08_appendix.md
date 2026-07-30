# 8. Appendix

SOP clause 12 item 8.

---

## A1. Glossary

| Term | Definition |
|---|---|
| **SBOM** | Software Bill of Materials — a formal inventory of every component in a piece of software |
| **CycloneDX** | An OWASP SBOM interchange standard; the format DepSentry emits |
| **SPDX** | An alternative SBOM standard (Linux Foundation) |
| **OSV** | Open Source Vulnerabilities — a distributed, machine-readable advisory database and schema |
| **CVE** | Common Vulnerabilities and Exposures — the public identifier scheme for real disclosed vulnerabilities |
| **CVSS** | Common Vulnerability Scoring System — a 0–10 severity score describing a vulnerability in the abstract |
| **EPSS** | Exploit Prediction Scoring System — probability a vulnerability will be exploited in the wild |
| **KEV** | CISA's Known Exploited Vulnerabilities catalogue |
| **CWE** | Common Weakness Enumeration — a taxonomy of defect classes |
| **SARIF** | Static Analysis Results Interchange Format — what CI security dashboards ingest |
| **VEX** | Vulnerability Exploitability eXchange — machine-readable "affected / not affected" assertions |
| **purl** | Package URL — a universal package identifier, e.g. `pkg:pypi/requests@2.28.0` |
| **AST** | Abstract Syntax Tree — the parsed structural representation of source code |
| **Call graph** | A directed graph whose edges are "function A can call function B" |
| **Entrypoint** | A function invoked from outside the program: `main`, a route handler, a CLI command, import-time code |
| **Reachability** | Whether a path exists in the call graph from an entrypoint to a target symbol |
| **Transitive dependency** | A package pulled in by another dependency rather than declared directly |
| **Alert fatigue** | Degraded response caused by a volume of alerts too high to triage, most of them unimportant |
| **Shift-left** | Moving security checks earlier in the development lifecycle |
| **Precision** | TP / (TP + FP) — of what was flagged, how much mattered |
| **Recall** | TP / (TP + FN) — of what mattered, how much was flagged |
| **MAP** | Mean Average Precision — ranking quality; 1.0 means all positives sorted to the top |
| **Ablation** | Removing one component to measure its individual contribution |

## A2. Advisory corpus summary

30 synthetic advisories across 16 packages. Full data in `data/seed_vulndb.py`;
browse interactively in the dashboard's *Advisory corpus* tab.

| Severity | Count |
|---|---|
| CRITICAL (9.0–10.0) | 1 |
| HIGH (7.0–8.9) | 10 |
| MEDIUM (4.0–6.9) | 16 |
| LOW (0.1–3.9) | 3 |
| **Total** | **30** |

Symbol coverage: **30/30 (100%)** — every advisory names its affected symbol, so
every one is traceable. Real OSV data is far sparser; §5.6 of the results
discusses the consequence.

Packages covered: requests, urllib3, jinja2, pyyaml, pillow, cryptography,
flask, werkzeug, numpy, pandas, sqlalchemy, certifi, idna, setuptools, click,
starlette, fastapi, pydantic, joblib, scikit-learn, matplotlib,
typing-extensions, anyio, h11.

## A3. References

**Standards and specifications**

1. OWASP CycloneDX SBOM Standard — https://cyclonedx.org/specification/overview/
2. SPDX Specification, Linux Foundation — https://spdx.dev/specifications/
3. OSV Schema — https://ossf.github.io/osv-schema/
4. SARIF 2.1.0, OASIS — https://docs.oasis-open.org/sarif/sarif/v2.1.0/
5. CVSS v3.1 Specification, FIRST — https://www.first.org/cvss/v3-1/specification-document
6. Package URL (purl) specification — https://github.com/package-url/purl-spec
7. CSAF / VEX, OASIS — https://oasis-open.github.io/csaf-documentation/
7a. OpenVEX Specification v0.2.0 — https://github.com/openvex/spec
7b. EPSS (Exploit Prediction Scoring System), FIRST — https://www.first.org/epss/
7c. OSV.dev API — https://google.github.io/osv.dev/api/
7d. Go Vulnerability Database (symbol-level advisory data) — https://vuln.go.dev/
7e. Anthropic Messages API — https://platform.claude.com/docs/en/api/messages
8. NIST SP 800-218, Secure Software Development Framework
9. Executive Order 14028, *Improving the Nation's Cybersecurity* (2021) — the origin of the US SBOM mandate
10. PEP 440, Version Identification and Dependency Specification
11. PEP 503, Simple Repository API (name normalisation)
12. PEP 621, Storing project metadata in pyproject.toml

**Tools surveyed**

13. `pip-audit`, PyPA — https://github.com/pypa/pip-audit
14. OSV-Scanner, Google — https://github.com/google/osv-scanner
15. Trivy, Aqua Security — https://github.com/aquasecurity/trivy
16. Dependabot, GitHub — https://docs.github.com/code-security/dependabot
17. `pycg` — Python call graph generation
18. Syft / Grype, Anchore — SBOM generation and matching

**Background reading**

19. OWASP Top 10 2021, A06: Vulnerable and Outdated Components
20. CISA Known Exploited Vulnerabilities Catalog
21. Python `ast` module documentation — https://docs.python.org/3/library/ast.html
22. Sonatype, *State of the Software Supply Chain* (annual)

> **[FILL]** Add any papers or standards your guide requires, and reformat to
> your school's citation style (IEEE is typical for engineering).

## A4. Ethics and academic integrity statement

*Addresses SOP clause 13.*

**Synthetic data — disclosed, not concealed.** The advisory corpus uses `DEPS-`
identifiers, deliberately *not* `CVE-` identifiers. The advisories are modelled
on the structure and severity distribution of real OSV records but are **not
claims about real defects in the named packages**. Presenting fabricated
advisories as real CVEs would defame the maintainers of those packages and would
be precisely the falsification clause 13 prohibits. The disclosure appears in
five places: the seeder's module docstring, the dashboard UI, the SOP compliance
matrix, §5.6 of the results, and here.

**No fabricated results.** Every figure in `docs/05_results_and_discussion.md`
is read from `reports/evaluation.json`, generated by `experiments/evaluate.py`
and reproducible from seed 42. No number was typed by hand.

**Negative results reported.** The ablation (§5.4) showed that the severity
threshold in our own design costs recall and gains nothing. It is reported as a
finding. The threshold was deliberately **not** retuned to make the headline
number look better, because tuning a parameter against the test set after seeing
the result would produce a better table and a worse experiment.

**Limitations stated.** §5.6 states plainly that the perfect ablation score
reflects the benchmark being generated by the same notion of reachability the
analyzer implements, and that real-world performance would be materially lower.

**No unauthorised testing.** DepSentry performs **static analysis only**. It
never imports, executes, or emulates the code it inspects, and never contacts a
remote host during a scan. No system was tested without authorisation.

**Responsible use.** The tool is defensive: it identifies vulnerable dependencies
so they can be fixed. It does not generate exploits.

**Plagiarism.** All prose is original. Run your institutional similarity check
before submission; clause 13 sets the limit at 15%.

**AI assistance — [FILL].** Declare per your institution's policy: state what
was AI-assisted and what was authored directly. The team should be able to
explain and defend every line of submitted code.

## A5. Sample output

Console:

```
  DepSentry  |  project_001
  --------------------------------------------------------------
  packages 7    findings 3    actionable 1    noise-cut 67%
  --------------------------------------------------------------
  #1  [HIGH] DEPS-2026-0018   certifi        risk  8.24  cvss 6.8  REACHABLE
       via core.handle -> core._process -> certifi.where

  2 finding(s) suppressed as unreachable.
```

Audit log verification:

```
OK: Audit chain intact; head = 870a4c1d9ac2e7b6.
```

SARIF fragment for a suppressed finding — visible in CI, not build-breaking:

```json
{
  "ruleId": "DEPS-2026-0007",
  "level": "note",
  "message": {
    "text": "pyyaml 5.4.1: Arbitrary code execution when untrusted input
             reaches the unsafe loader. [reachability=UNREACHABLE, risk=1.02]"
  },
  "properties": { "reachability": "UNREACHABLE", "actionable": false }
}
```

## A6. Environment

| Item | Value |
|---|---|
| Python | 3.14.0 (3.11+ required for `tomllib`) |
| Platform | macOS (Darwin 25.5.0); portable to Linux/Windows |
| Core dependencies | `cryptography`, `pandas` |
| Interface dependencies | `fastapi`, `uvicorn`, `pydantic`, `streamlit` |
| Test dependency | `pytest` |
| Tests | 187 pytest + 1 WASM engine test, all passing, ~1 s |
| Total Python | 6,943 lines across 35 files |
| Rust / JS | 523 + 433 lines |
| Optional network | OSV.dev, FIRST EPSS, Anthropic API — each degrades to offline |

## A7. Pre-submission checklist

- [ ] Replace every **[FILL]** marker across `docs/`
- [ ] Swap the representative subject list in `02_subject_contribution_matrix.md` §2 for your real Sem VII subjects
- [ ] Obtain the school sub-committee's Skill–NOS matrix; replace the indicative NOS codes in §3
- [ ] Confirm each subject has at least one deliverable (clause 7)
- [ ] Record team members (3–5, clause 8) and guide
- [ ] Fill actual review dates in `review_tracker.md` (clause 11.3)
- [ ] Complete `logbook.md` with real entries and division of work
- [ ] Arrange the external / industry evaluator (clause 11.1 — compulsory)
- [ ] Run the institutional plagiarism check (<15%, clause 13)
- [ ] Complete the AI-assistance declaration
- [ ] Submit the final report to the school office **through your project guide** (clause 11.1)
- [ ] Rehearse the demo in `06_final_project_report.md` §3
