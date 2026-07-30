"""End-to-end scan orchestration.

    project path
        -> SBOM generation
        -> advisory matching
        -> call graph + reachability
        -> risk fusion and ranking
        -> signed, audit-logged ScanResult
"""

from __future__ import annotations

from pathlib import Path

from .callgraph import build_call_graph
from .integrity import AuditLog, sign_sbom
from .models import Finding, ScanResult
from .reachability import ReachabilityAnalyzer
from .risk import score_findings
from .sbom import generate_sbom
from .vulndb import DEFAULT_DB, VulnerabilityDB


def scan_project(
    project_path: str | Path,
    *,
    db_path: str | Path = DEFAULT_DB,
    signing_key: bytes | str | Path | None = None,
    audit_log_path: str | Path | None = None,
    max_hops: int = 12,
) -> ScanResult:
    """Run a full DepSentry scan and return the result."""
    root = Path(project_path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    sbom = generate_sbom(root)

    graph = build_call_graph(root)
    analyzer = ReachabilityAnalyzer(graph, max_hops=max_hops)

    findings: list[Finding] = []
    with VulnerabilityDB(db_path) as db:
        for package, vuln in db.match_sbom(sbom.packages):
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

    score_findings(findings)

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
            },
        )

    return result
