# Project Logbook

Satisfies **SOP clause 10** — "maintain project records, logbooks, and
documentation".

> **[FILL] the dates and the team-member column.** The entries below record what
> was actually built and, importantly, what went wrong. Keep adding as you go —
> a logbook written retrospectively reads like one, and reviewers notice.

---

## How to use this

One entry per working session. Record what was attempted, what broke, and how it
was resolved. **Failed attempts are the most valuable entries** — they are the
evidence of engineering judgement that clause 14 ("higher-level thinking and
problem-solving") is asking for.

---

## Phase 1 — Problem Identification (Weeks 1–2)

### Entry 1 — [FILL date] · [FILL member]
**Goal:** Choose a Sem VII industry/research-oriented cybersecurity topic.

Surveyed candidates: adversarial robustness of ML-based IDS, zero-trust
continuous authentication, SOC alert triage, software supply chain risk.

Chose supply chain risk because it satisfies *both* halves of the clause 6.1
requirement — genuine industry demand (SBOM mandates, Log4Shell, xz-utils) and a
real research question (does reachability actually help, and by how much?).

Rejected the ML-IDS option: too close to existing coursework projects, and the
research contribution would be incremental.

### Entry 2 — [FILL date] · [FILL member]
**Goal:** Literature and tool survey.

Surveyed CycloneDX, SPDX, OSV, SARIF, pip-audit, Dependabot, Trivy, Snyk, pycg.

**Key finding:** OSV advisories frequently carry `ecosystem_specific.imports`
symbol data that almost no open-source consumer uses. Commercial SCA products
advertise "reachability" tiers but publish no methodology, so their suppressions
cannot be audited — a real problem when suppression is a security decision.

That gap became the project.

### Entry 3 — [FILL date] · [FILL member]
**Goal:** Fix the problem statement and state hypotheses.

Wrote H1 (volume) and H2 (ranking) **before** building anything, so the
experiment could not be retrofitted to whatever the tool happened to do.

Found the motivating example that made the idea concrete: `yaml.load` (CVSS 9.8)
vs `yaml.safe_load`. Same package, same version, same advisory — completely
different operational meaning. This became test #1.

---

## Phase 2 — Design and Planning (Weeks 3–4)

### Entry 4 — [FILL date] · [FILL member]
**Goal:** Architecture.

Settled on six stages with clean interfaces so each is independently testable.
Decided `models.py` and `callgraph.py` would be **stdlib-only**, so the analysis
core can be reused without dragging in FastAPI or pandas.

### Entry 5 — [FILL date] · [FILL member]
**Goal:** Design the verdict model.

First draft was **binary** — reachable or unreachable. Rejected it.

A binary model forces a false claim whenever the analysis is genuinely uncertain:
an advisory with no symbol data would have to be called "unreachable", which is
a silent false negative in a security tool. Replaced it with four states, where
UNKNOWN and POTENTIALLY_REACHABLE both mean *"cannot prove safety, so do not
claim it."*

This became design goal **G2, fail safe not silent**, and it shaped the rest of
the project.

### Entry 6 — [FILL date] · [FILL member]
**Goal:** Risk fusion model.

Tried an additive model first: `risk = CVSS + reachability_bonus`. It failed the
requirement immediately — a CVSS 9.8 unreachable finding still outranked a CVSS
5.0 reachable one, which is exactly the behaviour the project exists to fix.

Switched to multiplicative: 9.8 × 0.1 = 0.98 < 5.0 × 1.0 = 5.0. Correct.

Wrote `test_reachability_dominates_severity` so this property is asserted, not
merely intended.

---

## Phase 3 — Implementation (Weeks 5–6)

### Entry 7 — [FILL date] · [FILL member]
**Goal:** SBOM generator + advisory DB.

Built `sbom.py` (BFS over `importlib.metadata`) and `vulndb.py` (SQLite, OSV
schema). Seeded 30 advisories with 100% symbol coverage.

Deliberately used `DEPS-` identifiers rather than `CVE-`, so the corpus can never
be mistaken for claims about real defects in real packages.

### Entry 8 — [FILL date] · [FILL member]
**Goal:** Call graph and reachability.

Built the AST visitor: import tables, function registry, call resolution,
dynamic-dispatch detection.

**First end-to-end run worked on the first try** — on a demo app importing
requests, yaml and flask, the analyzer correctly marked `requests.get` REACHABLE
with a call path, and correctly marked the CVSS 9.8 `yaml.load` advisory
UNREACHABLE because the app called `safe_load`.

That was the moment the thesis was demonstrated rather than merely argued.

### Entry 9 — [FILL date] · [FILL member] — **BUG**
**Symptom:** Benchmark project scanned with 6 packages but produced only 1
finding. Expected far more.

**Diagnosis:** `generate_sbom()` always preferred the *installed* version over
the declared pin. Benchmark projects pinned `requests==2.28.0`, but the local
environment had 2.32.x, so the deliberately-vulnerable pins were being scanned as
patched versions.

**Fix:** retain the comparison operator during requirements parsing; an exact
`==` pin now wins over the environment. This is not just a benchmark fix — it is
**correct production behaviour**, since the pin is what actually deploys.

**Lesson:** the bug was only visible because the benchmark had known ground
truth. Without it, the tool would have looked like it was working.

### Entry 10 — [FILL date] · [FILL member]
**Goal:** Cryptographic integrity.

Ed25519 detached signatures with HMAC-SHA256 fallback, plus a hash-chained
append-only audit log. Used `hmac.compare_digest` rather than `==` to avoid a
timing side channel.

Excluded the timestamp from `canonical_bytes()` so an unchanged dependency set
produces an identical digest — otherwise every regeneration looks like a change
and signature comparison is useless for drift detection.

Wrote tests for both attack directions: editing a historical entry, and deleting
one.

### Entry 11 — [FILL date] · [FILL member]
**Goal:** CLI, REST API, dashboard.

Added `_safe_path()` to the API after realising the scan endpoint took an
arbitrary filesystem path — it would have let a caller walk the server's disk.
Now confined to an allow-listed root, 403 otherwise. Verified: `POST /scan` with
`/etc` returns 403.

Threat T3 in the threat model exists because of this session.

---

## Phase 4 — Evaluation and Documentation (Weeks 7–8)

### Entry 12 — [FILL date] · [FILL member]
**Goal:** Benchmark corpus.

Generated 40 projects with ground truth known *by construction* — the generator
decides whether to emit a call to the vulnerable symbol and records the decision.

Set `reach_rate = 0.35`, reflecting reported industry findings that only a
minority of dependency CVEs sit on an executed path. Realised corpus: 33.2%.

Seeded at 42 so every figure in the report is reproducible.

### Entry 13 — [FILL date] · [FILL member] — **BUG**
**Symptom:** `test_prerelease_sorts_below_release` failed — `parse_version("1.0.0a1")`
compared *greater* than `parse_version("1.0.0")`.

**Diagnosis:** naive token-tuple comparison. `1.0.0a1` produces a longer tuple,
and Python sorts the longer tuple higher. Backwards: a pre-release must sort
below its final release. Consequence in production would be **placing
pre-release users outside a range that genuinely affects them** — a false
negative in a security tool.

**Fix:** three-part comparison tuple `(release_quad, is_final, prerelease_tokens)`
with an explicit `is_final` flag, and the release quad zero-padded so `1.0` and
`1.0.0` compare equal.

**Lesson:** found by a test written for a boundary case nobody expected to
matter. Worth raising at Review 2.

### Entry 14 — [FILL date] · [FILL member]
**Goal:** Run the evaluation.

Both hypotheses supported. Precision 1.000 vs 0.318 for the CVSS gate; MAP 0.950
vs 0.512; alert volume 107 → 80.

Most interesting result was the **baseline's** poor showing: a CVSS ≥ 7.0 gate
achieves recall 0.395 — worse than a coin flip — while raising 73 false alarms.
That configuration is widely deployed in real CI pipelines.

### Entry 15 — [FILL date] · [FILL member] — **NEGATIVE RESULT**
**Goal:** Ablation — isolate which signal carries the result.

Reachability filter alone: P = 1.000, R = 1.000. Full DepSentry (reachability +
risk ≥ 4.0): P = 1.000, R = 0.930.

**The severity threshold cost 6 true positives and gained nothing.** All six are
the same advisory — `DEPS-2026-0021`, CVSS 3.3, fused risk 3.62, just under the
4.0 cutoff.

**Decision: report it, do not retune it.** Dropping the threshold to 3.5 would
produce recall 1.000 and a better-looking table, but tuning a parameter against
the test set after seeing the result is not a result — it is a nicer number.
Recorded as §5.4 of the results chapter.

### Entry 16 — [FILL date] · [FILL member]
**Goal:** Threats to validity.

Confronted the uncomfortable one: the benchmark is generated by the same notion
of reachability the analyzer implements, so P = R = 1.000 measures
**implementation correctness**, not real-world difficulty. Real code has dynamic
dispatch, DI, callbacks, monkey-patching, C extensions.

Stated it prominently in §5.6 rather than letting the headline number stand
unqualified, and made real-project validation the #1 future work item.

An unqualified "100% accuracy" claim would not survive an external evaluator's
first question, and would deserve not to.

### Entry 17 — [FILL date] · [FILL member]
**Goal:** Documentation set.

Wrote all eight clause-12 documents plus the SOP compliance traceability matrix,
this logbook, and the review tracker.

---

## Division of work — [FILL]

Clause 14 asks for evidence of teamwork and leadership; clause 11.2 assesses it
at 2.5 marks. Record it accurately.

| Member | PRN | Primary responsibility | Key artifacts |
|---|---|---|---|
| [FILL] | [FILL] | [FILL] | [FILL] |
| [FILL] | [FILL] | [FILL] | [FILL] |
| [FILL] | [FILL] | [FILL] | [FILL] |
| [FILL] | [FILL] | [FILL] | [FILL] |

## Guide meetings — [FILL]

| Date | Attendees | Discussion | Actions |
|---|---|---|---|
| [FILL] | | | |
