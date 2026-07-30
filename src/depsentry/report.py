"""Render scan results as Markdown, JSON, or SARIF.

SARIF matters for the industry story: it is what GitHub code scanning, Azure
DevOps and most CI dashboards ingest, so emitting it is what makes DepSentry
deployable rather than merely demonstrable.
"""

from __future__ import annotations

import json
from pathlib import Path

from .callgraph import render_path_detail
from .models import Finding, Reachability, ScanResult

_SEVERITY_ICON = {
    "CRITICAL": "[CRIT]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MED ]",
    "LOW": "[LOW ]",
    "NONE": "[INFO]",
}


def to_markdown(result: ScanResult) -> str:
    actionable = result.actionable_findings
    suppressed = [f for f in result.findings if not f.actionable]
    stats = result.stats

    lines = [
        f"# DepSentry Report: {result.project}",
        "",
        f"Scanned: {result.scanned_at}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Packages in SBOM | {len(result.sbom.packages)} "
        f"({stats.get('direct_dependencies', 0)} direct, "
        f"{stats.get('transitive_dependencies', 0)} transitive) |",
        f"| Total findings | {len(result.findings)} |",
        f"| **Actionable** | **{len(actionable)}** |",
        f"| Suppressed as unreachable | {len(suppressed)} |",
        f"| Noise reduction | {result.noise_reduction():.1%} |",
        f"| Entrypoints analysed | {stats.get('entrypoints', 0)} |",
        f"| Project functions | {stats.get('project_functions', 0)} |",
        f"| SBOM signed | {'yes' if stats.get('sbom_signed') else 'no'} |",
        "",
    ]

    if actionable:
        lines += [
            "## Actionable findings",
            "",
            "Ordered by fused risk score. Each carries a call path as evidence.",
            "",
        ]
        for f in actionable:
            v = f.vulnerability
            icon = _SEVERITY_ICON.get(v.severity.value, "")
            lines += [
                f"### {icon} #{f.rank} {v.vuln_id} - {f.package.name} {f.package.version}",
                "",
                f"{v.summary}",
                "",
                f"- **Risk score**: {f.risk_score:.2f} (CVSS {v.cvss_score}, "
                f"{v.severity.value})",
                f"- **Reachability**: {f.reachability.value}",
                f"- **Dependency**: {'direct' if f.package.direct else 'transitive via ' + ' -> '.join(f.package.parents)}",
                f"- **Fix**: {'upgrade to ' + v.fixed if v.fixed else 'no fixed version published'}",
                f"- **CWE**: {', '.join(v.cwe) if v.cwe else 'n/a'}",
                "",
            ]
            if f.call_paths:
                lines += ["**Evidence (call paths):**", "", "```"]
                lines += [f"  {p.render()}" for p in f.call_paths[:3]]
                lines += ["```", ""]

            if f.path_detail:
                lines += [
                    "**Traced path with source locations:**", "", "```text",
                    render_path_detail(f.path_detail), "```", "",
                ]

            if f.epss:
                lines += [
                    f"- **EPSS**: {f.epss.probability:.2%} probability of "
                    f"exploitation in 30 days ({f.epss.band}, "
                    f"{f.epss.percentile:.1%} percentile)",
                    "",
                ]

            if f.remediation_advice:
                lines += [
                    "**Suggested fix:**", "", f.remediation_advice, "",
                ]
            lines += ["<details><summary>Scoring rationale</summary>", ""]
            lines += [f"- {r}" for r in f.rationale]
            lines += ["", "</details>", ""]

    if suppressed:
        lines += [
            "## Suppressed findings",
            "",
            "Present in the dependency tree but not reachable from any "
            "entrypoint. Listed in full so suppression stays auditable.",
            "",
            "| Vuln | Package | CVSS | Risk | Verdict | Reason |",
            "|---|---|---|---|---|---|",
        ]
        for f in suppressed:
            reason = f.rationale[0] if f.rationale else ""
            lines.append(
                f"| {f.vulnerability.vuln_id} | {f.package.name} "
                f"{f.package.version} | {f.vulnerability.cvss_score} | "
                f"{f.risk_score:.2f} | {f.reachability.value} | {reason} |"
            )
        lines.append("")

    return "\n".join(lines)


def _code_flow(finding: Finding) -> dict | None:
    """Encode a traced call path as a SARIF threadFlow.

    SARIF 2.1.0 models exactly this: an ordered sequence of locations showing
    how execution arrives somewhere. Emitting it means GitHub's code scanning
    UI renders DepSentry's reachability evidence without any custom viewer.
    """
    if not finding.path_detail:
        return None

    locations = []
    for i, hop in enumerate(finding.path_detail):
        nxt = (
            finding.path_detail[i + 1]["function"]
            if i + 1 < len(finding.path_detail)
            else None
        )
        line = hop.get("call_line") or hop.get("line") or 1
        uri = hop["file"] if not hop.get("external") else "requirements.txt"
        text = (
            f"{hop['function']}() calls {nxt}()"
            if nxt
            else f"{hop['function']} -- vulnerable symbol"
        )
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": int(line)},
                },
                "message": {"text": text},
            },
            "nestingLevel": i,
        })

    return {"threadFlows": [{"locations": locations}]}


def to_sarif(result: ScanResult) -> dict:
    """SARIF 2.1.0 for CI ingestion."""
    rules = []
    results = []
    seen_rules: set[str] = set()

    for f in result.findings:
        v = f.vulnerability
        if v.vuln_id not in seen_rules:
            seen_rules.add(v.vuln_id)
            rules.append({
                "id": v.vuln_id,
                "name": f"DependencyVulnerability/{v.package}",
                "shortDescription": {"text": v.summary[:120]},
                "fullDescription": {"text": v.summary},
                "defaultConfiguration": {
                    "level": "error" if v.cvss_score >= 7 else "warning"
                },
                "properties": {
                    "security-severity": str(v.cvss_score),
                    "cwe": list(v.cwe),
                },
            })

        # Unreachable findings ship as "note" so they stay visible but never
        # break a build.
        level = "note" if not f.actionable else (
            "error" if v.cvss_score >= 7 else "warning"
        )
        message = (
            f"{v.package} {f.package.version}: {v.summary} "
            f"[reachability={f.reachability.value}, risk={f.risk_score:.2f}]"
        )
        if f.call_paths:
            message += f" Evidence: {f.call_paths[0].render()}"

        entry = {
            "ruleId": v.vuln_id,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "requirements.txt"},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "reachability": f.reachability.value,
                "riskScore": round(f.risk_score, 2),
                "actionable": f.actionable,
                "symbolSource": v.symbol_source,
                **({"cveId": v.cve_id} if v.cve_id else {}),
                **(
                    {
                        "epssProbability": round(f.epss.probability, 6),
                        "epssPercentile": round(f.epss.percentile, 6),
                    }
                    if f.epss
                    else {}
                ),
            },
        }

        # codeFlows renders the reachability path natively in GitHub code
        # scanning, so the evidence travels with the finding.
        flow = _code_flow(f)
        if flow:
            entry["codeFlows"] = [flow]
        if f.remediation_advice:
            entry["fixes"] = [{"description": {"text": f.remediation_advice}}]

        results.append(entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "DepSentry",
                "version": "1.0.0",
                "informationUri": "https://github.com/example/depsentry",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def write_reports(
    result: ScanResult, out_dir: str | Path, *, vex: bool = True
) -> dict[str, Path]:
    """Write markdown, JSON, SARIF, VEX and the CycloneDX SBOM.

    Returns a mapping of format name to written path.
    """
    directory = Path(out_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    slug = result.project

    paths = {
        "markdown": directory / f"{slug}_report.md",
        "json": directory / f"{slug}_findings.json",
        "sarif": directory / f"{slug}.sarif",
        "sbom": directory / f"{slug}_sbom.cdx.json",
    }

    paths["markdown"].write_text(to_markdown(result), encoding="utf-8")
    paths["json"].write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    paths["sarif"].write_text(json.dumps(to_sarif(result), indent=2), encoding="utf-8")

    if vex:
        from .vex import render_vex

        paths["vex"] = directory / "vex.json"
        paths["vex"].write_text(render_vex(result), encoding="utf-8")

    sbom_doc = result.sbom.to_cyclonedx()
    if result.sbom.signature:
        sbom_doc["signature"] = result.sbom.signature
    paths["sbom"].write_text(json.dumps(sbom_doc, indent=2), encoding="utf-8")

    return paths


def console_summary(result: ScanResult) -> str:
    """Compact terminal output for the CLI."""
    actionable = result.actionable_findings
    unknown = result.unknown_findings
    lines = [
        "",
        f"  DepSentry  |  {result.project}",
        f"  {'-' * 62}",
        f"  packages {len(result.sbom.packages):<4} "
        f"findings {len(result.findings):<4} "
        f"actionable {len(actionable):<4} "
        f"needs-review {len(unknown):<4} "
        f"noise-cut {result.noise_reduction():.0%}",
        f"  {'-' * 62}",
    ]

    if unknown:
        lines += [
            f"  {len(unknown)} finding(s) could NOT be assessed: the advisory names no",
            "  affected symbol, so reachability is undetermined. These are not",
            "  suppressed -- they need manual review.",
            "",
        ]

    if not actionable:
        if len(unknown) == len(result.findings) and unknown:
            lines += ["  No finding was assessable; nothing was suppressed.", ""]
        else:
            lines += ["  No actionable findings. All assessed matches are unreachable.", ""]
        return "\n".join(lines)

    for f in actionable[:15]:
        v = f.vulnerability
        lines.append(
            f"  #{f.rank:<2} {_SEVERITY_ICON.get(v.severity.value, '')} "
            f"{v.vuln_id:<16} {f.package.name:<14} "
            f"risk {f.risk_score:5.2f}  cvss {v.cvss_score:<4} "
            f"{f.reachability.value}"
        )
        if f.call_paths:
            lines.append(f"       via {f.call_paths[0].render()}")

    if len(actionable) > 15:
        lines.append(f"  ... and {len(actionable) - 15} more")

    suppressed = len(result.findings) - len(actionable)
    lines += ["", f"  {suppressed} finding(s) suppressed as unreachable.", ""]
    return "\n".join(lines)
