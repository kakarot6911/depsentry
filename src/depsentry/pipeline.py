"""End-to-end scan orchestration.

    project path
        -> SBOM generation
        -> advisory matching        (local corpus, or live from OSV.dev)
        -> call graph + reachability
        -> EPSS enrichment          (optional, live CVEs only)
        -> risk fusion and ranking
        -> LLM remediation          (optional, top-N reachable findings)
        -> signed, audit-logged ScanResult
"""

from __future__ import annotations

from pathlib import Path

from .callgraph import build_call_graph
from .integrity import AuditLog, sign_sbom
from .models import Finding, Reachability, ScanResult
from .reachability import ReachabilityAnalyzer
from .risk import score_findings
from .sbom import generate_sbom
from .vulndb import DEFAULT_DB, VulnerabilityDB


def _match_local(sbom, db_path) -> list[tuple]:
    with VulnerabilityDB(db_path) as db:
        return db.match_sbom(sbom.packages)


def _match_live(sbom, db_path, *, cache: bool, use_heuristic: bool, warn) -> tuple[list, dict]:
    """Fetch advisories from OSV.dev, falling back to the local corpus.

    Returns (matches, meta). `meta` carries the symbol-coverage numbers so the
    caller can surface them -- OSV's PyPI advisories carry no symbol data, and
    hiding that would make the reachability verdicts look better founded than
    they are.
    """
    from .osv_client import OSVClient, OSVUnavailable

    client = OSVClient(use_heuristic=use_heuristic)
    try:
        matches = client.advisories_for(sbom.packages)
    except OSVUnavailable as exc:
        warn(f"OSV.dev unreachable ({exc}); falling back to the local advisory corpus.")
        return _match_local(sbom, db_path), {"live": False, "fallback": True}

    if cache and matches:
        with VulnerabilityDB(db_path) as db:
            cached = db.import_osv_advisories([v for _, v in matches])
        warn(f"Cached {cached} new advisory row(s) into {db_path}.")

    return matches, {
        "live": True,
        "fallback": False,
        "symbol_coverage": round(client.stats.symbol_coverage, 4),
        "advisories_found": client.stats.advisories_found,
        "symbols_upstream": client.stats.with_upstream_symbols,
        "symbols_overlay": client.stats.with_overlay_symbols,
        "symbols_missing": client.stats.without_symbols,
        "coverage_report": client.coverage_report(),
    }


def scan_project(
    project_path: str | Path,
    *,
    db_path: str | Path = DEFAULT_DB,
    signing_key: bytes | str | Path | None = None,
    audit_log_path: str | Path | None = None,
    max_hops: int = 12,
    live: bool = False,
    cache_live: bool = False,
    overlay_heuristic: bool = False,
    epss: bool = True,
    remediation_limit: int = 0,
    warn=None,
) -> ScanResult:
    """Run a full DepSentry scan and return the result.

    Defaults are unchanged from v1.0: local corpus, no network. `live`, `epss`
    and `remediation_limit` are opt-in and each degrade gracefully.
    """
    root = Path(project_path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    warn = warn or (lambda _msg: None)
    sbom = generate_sbom(root)

    graph = build_call_graph(root)
    analyzer = ReachabilityAnalyzer(graph, max_hops=max_hops)

    live_meta: dict = {"live": False}
    if live:
        pairs, live_meta = _match_live(
            sbom, db_path, cache=cache_live, use_heuristic=overlay_heuristic, warn=warn
        )
    else:
        pairs = _match_local(sbom, db_path)

    findings: list[Finding] = []
    for package, vuln in pairs:
        verdict = analyzer.analyze(vuln)
        findings.append(
            Finding(
                vulnerability=vuln,
                package=package,
                reachability=verdict.status,
                call_paths=verdict.call_paths,
                rationale=[verdict.reason],
            )
        )

    # -- EPSS enrichment ------------------------------------------------
    epss_meta: dict = {"enabled": False}
    if epss and findings:
        from .epss_client import EPSSClient, EPSSUnavailable

        cve_ids = sorted({f.vulnerability.cve_id for f in findings if f.vulnerability.cve_id})
        if cve_ids:
            try:
                scores = EPSSClient().scores_for(cve_ids)
                for f in findings:
                    cve = f.vulnerability.cve_id
                    if cve and cve in scores:
                        f.epss = scores[cve]
                epss_meta = {
                    "enabled": True,
                    "cves_queried": len(cve_ids),
                    "scores_found": len(scores),
                }
            except EPSSUnavailable as exc:
                warn(f"EPSS unavailable ({exc}); scoring without exploit-probability data.")
                epss_meta = {"enabled": False, "error": str(exc)}

    score_findings(findings)

    # -- LLM remediation ------------------------------------------------
    remediation_meta: dict = {"enabled": False}
    if remediation_limit > 0:
        from .remediation import RemediationEngine

        engine = RemediationEngine()
        if engine.available:
            targets = [
                f for f in findings if f.reachability is Reachability.REACHABLE
            ][:remediation_limit]
            generated = engine.annotate(targets, project_root=root)
            remediation_meta = {
                "enabled": True,
                "generated": generated,
                "considered": len(targets),
                "model": engine.model,
            }
        else:
            warn(
                "Tip: set ANTHROPIC_API_KEY to get AI-powered remediation suggestions."
            )

    if signing_key is not None:
        sign_sbom(sbom, signing_key)

    reach_counts: dict[str, int] = {}
    for f in findings:
        reach_counts[f.reachability.value] = reach_counts.get(f.reachability.value, 0) + 1

    result = ScanResult(
        project=sbom.project,
        sbom=sbom,
        findings=findings,
        entrypoints=graph.entrypoints,
        stats={
            **analyzer.summary(),
            "direct_dependencies": sum(1 for p in sbom.packages if p.direct),
            "transitive_dependencies": sum(1 for p in sbom.packages if not p.direct),
            "reachability_breakdown": reach_counts,
            "sbom_signed": sbom.signature is not None,
            "advisory_source": live_meta,
            "epss": epss_meta,
            "remediation": remediation_meta,
        },
    )

    if audit_log_path is not None:
        AuditLog(audit_log_path).append(
            "scan",
            {
                "project": result.project,
                "packages": len(sbom.packages),
                "total_findings": len(findings),
                "actionable": len(result.actionable_findings),
                "noise_reduction": round(result.noise_reduction(), 4),
                "live": bool(live_meta.get("live")),
            },
        )

    return result
