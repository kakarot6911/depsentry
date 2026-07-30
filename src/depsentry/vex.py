"""OpenVEX document generation from scan results.

VEX (Vulnerability Exploitability eXchange) is how a producer tells consumers
"this CVE appears in our SBOM but does not affect us, and here is why". CISA,
NTIA and the EU Cyber Resilience Act all point at it.

The usual problem with VEX is that the justification is asserted by a human and
cannot be checked. DepSentry derives it: a `not_affected` statement is backed by
a call-graph result, and an `affected` statement carries the actual call path.

Spec: https://github.com/openvex/spec (OpenVEX v0.2.0)

## Verdict mapping

| DepSentry verdict     | VEX status          | Justification                  |
|-----------------------|---------------------|--------------------------------|
| UNREACHABLE           | not_affected        | vulnerable_code_not_present*   |
| REACHABLE             | affected            | (action_statement instead)     |
| UNKNOWN               | under_investigation | (no justification permitted)   |
| POTENTIALLY_REACHABLE | under_investigation | (no justification permitted)   |

*OpenVEX defines a fixed justification vocabulary. The correct label for "the
code is present but never executed" is `vulnerable_code_not_in_execute_path`;
`vulnerable_code_not_present` is reserved for the case where the vulnerable
component was stripped entirely. DepSentry uses the former, which is what its
analysis actually establishes.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from .models import Finding, Reachability, ScanResult

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
TOOL_NAME = "DepSentry"
TOOL_VERSION = "1.1.0"

# The OpenVEX justification vocabulary (spec section "Justification").
JUSTIFICATION_NOT_IN_PATH = "vulnerable_code_not_in_execute_path"

STATUS_NOT_AFFECTED = "not_affected"
STATUS_AFFECTED = "affected"
STATUS_UNDER_INVESTIGATION = "under_investigation"


def _vuln_url(vuln_id: str) -> str:
    """Canonical URL for an advisory identifier."""
    if vuln_id.upper().startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    return f"https://osv.dev/vulnerability/{vuln_id}"


def _impact_statement(finding: Finding) -> str:
    """Human-readable explanation of the verdict, carrying the evidence."""
    symbols = ", ".join(finding.vulnerability.affected_symbols) or "the affected code"
    package = f"{finding.package.name} {finding.package.version}"

    if finding.reachability is Reachability.UNREACHABLE:
        if not finding.vulnerability.affected_symbols:
            return (
                f"{package} is present but no call path to the affected code was "
                "found by static analysis."
            )
        return (
            f"Static call-graph analysis found no path from any application "
            f"entrypoint to {symbols} in {package}. The vulnerable code is "
            f"present in the dependency tree but is never executed."
        )

    if finding.reachability is Reachability.REACHABLE:
        if finding.call_paths:
            return (
                f"Reachable via: {finding.call_paths[0].render()}. "
                f"The vulnerable symbol {symbols} is invoked from application code."
            )
        return f"{symbols} in {package} is reachable from application code."

    if finding.reachability is Reachability.POTENTIALLY_REACHABLE:
        return (
            f"{package} is imported and the importing module uses dynamic dispatch "
            "(getattr/eval). Static analysis cannot confirm whether "
            f"{symbols} is invoked. Manual review recommended."
        )

    return (
        f"Advisory {finding.vulnerability.vuln_id} does not name a specific "
        "affected symbol, so reachability could not be determined. Manual review "
        "recommended."
    )


def _action_statement(finding: Finding) -> str | None:
    """What to do about an affected finding."""
    if finding.reachability is not Reachability.REACHABLE:
        return None

    package = finding.package.name
    fixed = finding.vulnerability.fixed
    symbols = ", ".join(finding.vulnerability.affected_symbols) or "the affected API"

    if fixed:
        action = f"Upgrade {package} to {fixed} or later"
    else:
        action = f"No fixed version is published for {package}; apply a mitigation"

    action += f", or refactor to avoid calling {symbols}."

    if finding.epss and finding.epss.probability >= 0.3:
        action += (
            f" Prioritise: EPSS puts exploitation probability at "
            f"{finding.epss.probability:.1%} over the next 30 days."
        )
    return action


def statement_for(finding: Finding) -> dict:
    """Build one OpenVEX statement from a finding."""
    vuln = finding.vulnerability
    identifier = vuln.cve_id or vuln.osv_id or vuln.vuln_id

    statement: dict = {
        "vulnerability": {
            "@id": _vuln_url(identifier),
            "name": identifier,
            "description": vuln.summary,
        },
        "products": [
            {
                "@id": finding.package.purl,
                "subcomponents": [{"@id": finding.package.purl}],
            }
        ],
        "impact_statement": _impact_statement(finding),
    }

    if finding.reachability is Reachability.UNREACHABLE:
        statement["status"] = STATUS_NOT_AFFECTED
        # OpenVEX requires either a justification or an impact_statement on
        # not_affected; supplying both is permitted and more useful.
        statement["justification"] = JUSTIFICATION_NOT_IN_PATH
    elif finding.reachability is Reachability.REACHABLE:
        statement["status"] = STATUS_AFFECTED
        statement["action_statement"] = _action_statement(finding)
        statement["action_statement_timestamp"] = datetime.now(timezone.utc).isoformat()
    else:
        statement["status"] = STATUS_UNDER_INVESTIGATION

    # Non-standard extras are namespaced so a strict consumer can ignore them.
    statement["depsentry:analysis"] = {
        "reachability": finding.reachability.value,
        "risk_score": round(finding.risk_score, 2),
        "cvss": vuln.cvss_score,
        "symbol_source": vuln.symbol_source,
        "affected_symbols": list(vuln.affected_symbols),
        "call_paths": [p.render() for p in finding.call_paths],
        "epss": (
            {"probability": finding.epss.probability, "percentile": finding.epss.percentile}
            if finding.epss
            else None
        ),
    }
    return statement


def build_vex(result: ScanResult, *, author: str | None = None) -> dict:
    """Assemble a complete OpenVEX document for a scan."""
    now = datetime.now(timezone.utc).isoformat()
    document_id = f"https://depsentry.local/vex/urn:uuid:{uuid.uuid4()}"

    return {
        "@context": OPENVEX_CONTEXT,
        "@id": document_id,
        "author": author or f"{TOOL_NAME} Automated Analysis",
        "role": "tool",
        "timestamp": now,
        "last_updated": now,
        "version": 1,
        "tooling": f"{TOOL_NAME} v{TOOL_VERSION}",
        "statements": [statement_for(f) for f in result.findings],
    }


def render_vex(result: ScanResult, *, author: str | None = None, indent: int = 2) -> str:
    """Serialise the OpenVEX document."""
    return json.dumps(build_vex(result, author=author), indent=indent)


def vex_summary(result: ScanResult) -> dict[str, int]:
    """Count statements by VEX status -- handy for CLI output and the dashboard."""
    counts = {
        STATUS_NOT_AFFECTED: 0,
        STATUS_AFFECTED: 0,
        STATUS_UNDER_INVESTIGATION: 0,
    }
    for finding in result.findings:
        if finding.reachability is Reachability.UNREACHABLE:
            counts[STATUS_NOT_AFFECTED] += 1
        elif finding.reachability is Reachability.REACHABLE:
            counts[STATUS_AFFECTED] += 1
        else:
            counts[STATUS_UNDER_INVESTIGATION] += 1
    return counts
