"""Live characterization study: DepSentry against real OSV.dev advisories.

## Why this is not a precision/recall benchmark

`evaluate.py` can report precision, recall, F1 and MAP because the synthetic
corpus has ground truth **by construction** -- the generator decided whether to
emit a call to each vulnerable symbol and recorded that decision.

Real advisories have no such labels, and the IDs do not even line up: ground
truth is keyed to `DEPS-` identifiers while OSV returns `GHSA-` / `PYSEC-`.
Overlap is exactly zero. Establishing ground truth for real advisories would
require manually reading each one, identifying the affected function, and
auditing every benchmark project for a call to it -- that is the future-work
item in `docs/05` §5.9, not something this script can synthesise.

**So this script deliberately reports no precision, recall, F1 or MAP.**
Printing those numbers here would mean inventing labels.

## What it does measure

Everything obtainable without labels, at corpus scale:

1. **Symbol coverage** -- the fraction of real advisories carrying the data
   reachability analysis depends on. This is the study's headline.
2. **Advisory volume** -- real alert load vs the synthetic corpus.
3. **Verdict distribution** -- how many findings land UNKNOWN because the
   advisory names no symbol.
4. **Overlay efficacy** -- how many findings the curated symbol overlay rescues
   from UNKNOWN, and what they resolve to.
5. **Alert volume** -- DepSentry vs a CVSS >= 7.0 gate. Volume is comparable
   without labels; *correctness* of that volume is not.

## Network etiquette

One batched query over the corpus's 16 unique packages, then one detail fetch
per unique advisory, cached to a dedicated SQLite file. All 40 project scans
then run offline against that cache. Re-runs need no network at all.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from depsentry.models import Package, Reachability  # noqa: E402
from depsentry.osv_client import OSVClient, OSVUnavailable, SymbolOverlay  # noqa: E402
from depsentry.pipeline import scan_project  # noqa: E402
from depsentry.sbom import generate_sbom  # noqa: E402
from depsentry.vulndb import VulnerabilityDB  # noqa: E402

BENCHMARK_DIR = ROOT / "benchmark"
REPORTS_DIR = ROOT / "reports"
LIVE_DB = ROOT / "data" / "vulndb_live.sqlite3"

CVSS_GATE = 7.0


def collect_packages() -> list[Package]:
    """Union of every package/version pinned across the benchmark corpus."""
    seen: dict[str, Package] = {}
    for project in sorted(BENCHMARK_DIR.iterdir()):
        if not project.is_dir():
            continue
        for pkg in generate_sbom(project).packages:
            if pkg.direct:
                seen.setdefault(pkg.purl, pkg)
    return sorted(seen.values(), key=lambda p: (p.name, p.version))


def fetch_live_corpus(packages: list[Package], *, use_heuristic: bool) -> dict:
    """One batched fetch, cached to LIVE_DB. Returns coverage statistics."""
    client = OSVClient(use_heuristic=use_heuristic)
    matches = client.advisories_for(packages)

    with VulnerabilityDB(LIVE_DB) as db:
        db.import_osv_advisories([v for _, v in matches])
        total = db.count()

    return {
        "packages_queried": client.stats.packages_queried,
        "advisories_found": client.stats.advisories_found,
        "advisory_rows_cached": total,
        "with_cvss": client.stats.with_cvss,
        "symbols_upstream": client.stats.with_upstream_symbols,
        "symbols_overlay": client.stats.with_overlay_symbols,
        "symbols_missing": client.stats.without_symbols,
        "symbol_coverage_upstream": round(
            client.stats.with_upstream_symbols
            / max(client.stats.with_upstream_symbols + client.stats.without_symbols
                  + client.stats.with_overlay_symbols, 1),
            4,
        ),
        "errors": len(client.stats.errors),
    }


def scan_corpus(db_path: Path, *, overlay_symbols: dict[str, list[str]] | None = None) -> dict:
    """Scan all benchmark projects offline against the cached real advisories."""
    verdicts: Counter[str] = Counter()
    totals = {
        "projects": 0, "findings": 0, "actionable": 0,
        "unknown": 0, "assessed": 0, "cvss_gate_alerts": 0,
    }
    per_project = []

    for project in sorted(BENCHMARK_DIR.iterdir()):
        if not project.is_dir():
            continue
        result = scan_project(project, db_path=db_path, epss=False)
        totals["projects"] += 1
        totals["findings"] += len(result.findings)
        totals["actionable"] += len(result.actionable_findings)
        totals["unknown"] += len(result.unknown_findings)
        totals["assessed"] += len(result.assessed_findings)
        totals["cvss_gate_alerts"] += sum(
            1 for f in result.findings if f.vulnerability.cvss_score >= CVSS_GATE
        )
        for f in result.findings:
            verdicts[f.reachability.value] += 1
        per_project.append({
            "project": project.name,
            "findings": len(result.findings),
            "actionable": len(result.actionable_findings),
            "unknown": len(result.unknown_findings),
        })

    return {"totals": totals, "verdicts": dict(verdicts), "per_project": per_project}


def _build_overlay_db(source: Path, dest: Path) -> int:
    """Copy the cached corpus and add overlay symbols to the copy.

    The upstream cache is left pristine. Mutating it in place made a re-run
    report 92.6% "upstream" coverage on data the overlay had supplied -- the
    two arms must not share a mutable store.
    """
    import shutil

    dest.unlink(missing_ok=True)
    shutil.copyfile(source, dest)

    overlay = SymbolOverlay()
    updated = 0
    with VulnerabilityDB(dest) as db:
        for vuln in db.all_advisories():
            if vuln.affected_symbols:
                continue
            symbols = overlay.lookup(
                vuln.vuln_id, (vuln.cve_id,) if vuln.cve_id else (),
                vuln.package, use_heuristic=True,
            )
            if symbols:
                from dataclasses import replace

                db.add(replace(vuln, affected_symbols=symbols, symbol_source="overlay"))
                updated += 1
    return updated


def run(*, refresh: bool = False) -> dict:
    packages = collect_packages()
    print(f"Corpus: {len(packages)} unique pinned packages across the benchmark.\n")

    fetch_stats: dict = {}
    if refresh or not LIVE_DB.exists():
        print("Fetching real advisories from OSV.dev (one batch + per-advisory detail)...")
        try:
            fetch_stats = fetch_live_corpus(packages, use_heuristic=False)
        except OSVUnavailable as exc:
            print(f"OSV.dev unreachable: {exc}")
            print("Cannot run the live study without network access.")
            return {"error": str(exc)}
        print("  done.\n")
    else:
        with VulnerabilityDB(LIVE_DB) as db:
            advisories = db.all_advisories()
        # Count by provenance, never by "has symbols" -- an overlay-supplied
        # symbol is not upstream data, and conflating them would report a
        # coverage figure that is simply false.
        upstream = sum(1 for a in advisories if a.symbol_source == "upstream")
        fetch_stats = {
            "advisory_rows_cached": len(advisories),
            "symbols_upstream": upstream,
            "symbols_overlay": sum(1 for a in advisories if a.symbol_source == "overlay"),
            "symbols_missing": len(advisories) - upstream,
            "symbol_coverage_upstream": round(upstream / max(len(advisories), 1), 4),
            "note": "reused cached corpus; pass --refresh to re-fetch",
        }
        print(f"Reusing cached live corpus ({len(advisories)} advisory rows).\n")

    print("Scanning 40 projects against real advisories (upstream symbols only)...")
    baseline_arm = scan_corpus(LIVE_DB)

    print("Applying symbol overlay to a copy and re-scanning...")
    overlay_db = LIVE_DB.with_name("vulndb_live_overlay.sqlite3")
    overlaid = _build_overlay_db(LIVE_DB, overlay_db)
    overlay_arm = scan_corpus(overlay_db)
    print(f"  overlay supplied symbols for {overlaid} advisory row(s).\n")

    # Synthetic comparison, read from the existing evaluation for context.
    synthetic = {}
    eval_path = REPORTS_DIR / "evaluation.json"
    if eval_path.exists():
        doc = json.loads(eval_path.read_text())
        synthetic = {
            "advisory_instances": doc["corpus"]["advisory_instances_scored"],
            "depsentry_alerts": doc["headline"]["alert_volume_depsentry"],
            "cvss_gate_alerts": doc["headline"]["alert_volume_cvss7"],
        }

    report = {
        "study_type": "characterization (no ground truth available)",
        "metrics_deliberately_absent": [
            "precision", "recall", "f1", "MAP",
            "reason: real advisories carry no reachability labels, and OSV ids "
            "(GHSA-/PYSEC-) have zero overlap with the synthetic ground-truth "
            "ids (DEPS-). Producing these would require inventing labels.",
        ],
        "fetch": fetch_stats,
        "arm_upstream_only": baseline_arm,
        "arm_with_overlay": overlay_arm,
        "overlay_rows_applied": overlaid,
        "synthetic_comparison": synthetic,
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "evaluation_live.json").write_text(json.dumps(report, indent=2))
    _write_markdown(report, REPORTS_DIR / "evaluation_live.md")
    return report


def _write_markdown(r: dict, path: Path) -> None:
    up, ov = r["arm_upstream_only"], r["arm_with_overlay"]
    f = r["fetch"]
    ut, ot = up["totals"], ov["totals"]

    def pct(n, d):
        return f"{(n / d * 100):.1f}%" if d else "n/a"

    lines = [
        "# DepSentry — Live Characterization Study",
        "",
        "Generated by `experiments/evaluate_live.py` against **real OSV.dev advisories**.",
        "",
        "> ## This is not a precision/recall benchmark",
        ">",
        "> Real advisories carry no reachability labels, and OSV identifiers",
        "> (`GHSA-`/`PYSEC-`) have **zero overlap** with the synthetic corpus's",
        "> ground-truth identifiers (`DEPS-`). Precision, recall, F1 and MAP are",
        "> therefore **structurally unobtainable** here — reporting them would mean",
        "> inventing labels. They are deliberately absent.",
        ">",
        "> For labelled metrics see `reports/evaluation.md` (synthetic corpus).",
        "",
        "## 1. Symbol coverage — the headline",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Advisory records processed | {f.get('symbols_upstream', 0) + f.get('symbols_overlay', 0) + f.get('symbols_missing', 0)} |",
        f"| **With upstream symbol data** | **{f.get('symbols_upstream', 0)}** |",
        f"| Without symbol data | {f.get('symbols_missing', 0)} |",
        f"| **Upstream symbol coverage** | **{f.get('symbol_coverage_upstream', 0):.1%}** |",
        f"| Unique rows cached (deduplicated) | {f.get('advisory_rows_cached', 0)} |",
        "",
        "*Records processed exceeds unique rows because one advisory can declare",
        "several disjoint affected ranges; each is a separate record, deduplicated",
        "on (advisory, package, introduced) when cached.*",
        "",
        "Reachability analysis needs the affected symbol. OSV has the field",
        "(`affected[].ecosystem_specific.imports[]`); the Python advisory sources",
        "do not populate it.",
        "",
        "## 2. Verdict distribution",
        "",
        "| Verdict | Upstream only | With overlay |",
        "|---|---|---|",
    ]
    for verdict in ("REACHABLE", "POTENTIALLY_REACHABLE", "UNREACHABLE", "UNKNOWN"):
        lines.append(
            f"| {verdict} | {up['verdicts'].get(verdict, 0)} | {ov['verdicts'].get(verdict, 0)} |"
        )

    lines += [
        "",
        "## 3. Alert volume across 40 projects",
        "",
        "| Condition | Upstream only | With overlay |",
        "|---|---|---|",
        f"| Total findings | {ut['findings']} | {ot['findings']} |",
        f"| CVSS >= 7.0 gate would alert | {ut['cvss_gate_alerts']} | {ot['cvss_gate_alerts']} |",
        f"| DepSentry actionable | {ut['actionable']} | {ot['actionable']} |",
        f"| **Unassessable (UNKNOWN)** | **{ut['unknown']}** | **{ot['unknown']}** |",
        f"| Assessed | {ut['assessed']} | {ot['assessed']} |",
        "",
        f"Without the overlay, **{pct(ut['unknown'], ut['findings'])}** of real findings "
        "could not be assessed at all.",
        f"The overlay reduces that to **{pct(ot['unknown'], ot['findings'])}** "
        f"({r['overlay_rows_applied']} advisory rows given symbols).",
        "",
        "> ⚠ The overlay is a **curated heuristic**, not upstream fact. It attributes a",
        "> library's known dangerous API surface to advisories on that library, which is",
        "> sometimes wrong. It errs toward REACHABLE (a false positive) rather than",
        "> hiding findings, and every finding records its `symbol_source`.",
        "",
    ]

    if r.get("synthetic_comparison"):
        s = r["synthetic_comparison"]
        lines += [
            "## 4. Real vs synthetic advisory load",
            "",
            "| | Synthetic corpus | Live OSV |",
            "|---|---|---|",
            f"| Advisory instances | {s['advisory_instances']} | {ut['findings']} |",
            f"| CVSS gate alerts | {s['cvss_gate_alerts']} | {ut['cvss_gate_alerts']} |",
            f"| DepSentry actionable | {s['depsentry_alerts']} | {ut['actionable']} |",
            "",
            "The synthetic corpus understates real alert load; the ratio is the",
            "practical argument for triage, independent of any labelled metric.",
            "",
        ]

    lines += [
        "## 5. What this study establishes",
        "",
        "1. The reachability method is **blocked in practice for PyPI** by upstream",
        "   advisory data, not by analysis technique.",
        "2. A curated symbol overlay restores usefulness, at the cost of a documented,",
        "   opt-in heuristic.",
        "3. The highest-value contribution to the ecosystem is **advisory symbol data**.",
        "   Go's vulndb shows the format works at scale.",
        "",
        "*Numbers here move as OSV updates. The seed-42 synthetic figures in",
        "`reports/evaluation.md` remain the reproducible, citable results.*",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    result = run(refresh="--refresh" in sys.argv)
    if "error" in result:
        raise SystemExit(1)

    up, ov = result["arm_upstream_only"]["totals"], result["arm_with_overlay"]["totals"]
    f = result["fetch"]
    print("=== Live characterization study ===")
    print(f"advisory rows cached     : {f.get('advisory_rows_cached', 0)}")
    print(f"upstream symbol coverage : {f.get('symbol_coverage_upstream', 0):.1%}")
    print()
    print(f"{'':26} {'upstream':>10} {'overlay':>10}")
    for label, key in (("total findings", "findings"), ("CVSS>=7 would alert", "cvss_gate_alerts"),
                       ("DepSentry actionable", "actionable"), ("UNASSESSABLE (UNKNOWN)", "unknown")):
        print(f"{label:26} {up[key]:>10} {ov[key]:>10}")
    print()
    print("precision/recall/F1/MAP: deliberately absent -- no ground truth exists")
    print("for real advisories. See the header of reports/evaluation_live.md.")
    print()
    print("Wrote reports/evaluation_live.{json,md}")
