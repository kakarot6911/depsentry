"""Risk fusion: turn CVSS plus context into a single prioritisation score.

The baseline every scanner uses is `score = CVSS`. That ranks a critical RCE in
an unreachable code path above a medium-severity flaw sitting directly on a
request handler, which is backwards from an exploitability standpoint.

DepSentry's score multiplies severity by evidence:

    risk = CVSS
           x reachability_weight     (0.1 unreachable .. 1.0 reachable)
           x exposure_factor         (network-facing paths matter more)
           x dependency_factor       (direct deps are cheaper to fix)
           x fix_factor              (an available patch raises actionability)
           x exploit_factor          (known exploitation dominates everything)

Every multiplier is bounded and the result is clamped to 0..10 so the output
stays on the CVSS scale reviewers already read fluently.
"""

from __future__ import annotations

from .models import Finding, Reachability

# Weight bounds are configuration, not magic numbers: they are stated here and
# justified in docs/03_design_document.md so an evaluator can challenge them.
EXPOSURE_NETWORK = 1.15
EXPOSURE_LOCAL = 0.95
DIRECT_DEP = 1.10
TRANSITIVE_DEP = 0.90
DEEP_TRANSITIVE_DEP = 0.80
FIX_AVAILABLE = 1.05
NO_FIX = 0.85
EXPLOIT_KNOWN = 1.30
NO_EXPLOIT = 1.0

# EPSS multipliers. Thresholds follow the shape of the published EPSS
# distribution: >=0.7 is roughly the top 1% of all scored CVEs, >=0.3 the top
# few percent. Absent data is neutral (1.0), never punitive -- most advisories
# have no CVE alias and therefore no score, and they must not be demoted for it.
EPSS_CRITICAL = 1.40   # p >= 0.70 : actively exploited in the wild
EPSS_HIGH = 1.20       # p >= 0.30
EPSS_MODERATE = 1.05   # p >= 0.10
EPSS_LOW = 0.90        # p <  0.10 : real, but nobody is exploiting it
EPSS_ABSENT = 1.00     # no score available

ACTIONABLE_THRESHOLD = 4.0


def exposure_factor(finding: Finding) -> float:
    return EXPOSURE_NETWORK if finding.vulnerability.network_exposed else EXPOSURE_LOCAL


def dependency_factor(finding: Finding) -> float:
    pkg = finding.package
    if pkg.direct:
        return DIRECT_DEP
    return DEEP_TRANSITIVE_DEP if pkg.depth >= 2 else TRANSITIVE_DEP


def fix_factor(finding: Finding) -> float:
    return FIX_AVAILABLE if finding.vulnerability.has_fix else NO_FIX


def exploit_factor(finding: Finding) -> float:
    return EXPLOIT_KNOWN if finding.vulnerability.exploit_known else NO_EXPLOIT


def epss_factor(finding: Finding) -> float:
    """Multiplier derived from exploit probability.

    Deliberately bounded to [0.90, 1.40] so EPSS *modulates* the ranking but can
    never override reachability. A 10.0-CVSS unreachable finding with maximum
    EPSS still scores 10.0 x 0.1 x 1.40 = 1.40, below a mid-severity reachable
    one -- which is the ordering the whole project argues for.
    """
    if finding.epss is None:
        return EPSS_ABSENT
    p = finding.epss.probability
    if p >= 0.70:
        return EPSS_CRITICAL
    if p >= 0.30:
        return EPSS_HIGH
    if p >= 0.10:
        return EPSS_MODERATE
    return EPSS_LOW


def compute_risk(finding: Finding) -> float:
    """Composite risk score on the 0-10 CVSS scale."""
    v = finding.vulnerability
    score = (
        v.cvss_score
        * finding.reachability.weight
        * exposure_factor(finding)
        * dependency_factor(finding)
        * fix_factor(finding)
        * exploit_factor(finding)
        * epss_factor(finding)
    )
    return max(0.0, min(10.0, score))


def compute_baseline(finding: Finding) -> float:
    """The control condition: severity only, exactly what a CVSS-gate does."""
    return finding.vulnerability.cvss_score


def explain(finding: Finding) -> list[str]:
    """Human-readable justification for the score.

    Required by the design: an unexplained ranking is one a developer will not
    trust, and a suppression they cannot audit is a liability.
    """
    v = finding.vulnerability
    lines = [
        f"Base CVSS {v.cvss_score} ({v.severity.value}).",
        f"Reachability {finding.reachability.value} "
        f"(x{finding.reachability.weight:.2f}).",
    ]

    if finding.call_paths:
        lines.append(f"Evidence: {finding.call_paths[0].render()}")

    if v.network_exposed:
        lines.append(f"Advisory is network-reachable (x{EXPOSURE_NETWORK}).")
    if v.exploit_known:
        lines.append(f"Public exploitation reported (x{EXPLOIT_KNOWN}).")

    if finding.epss is not None:
        lines.append(
            f"EPSS {finding.epss.probability:.1%} probability of exploitation "
            f"in 30 days ({finding.epss.band}, {finding.epss.percentile:.1%} "
            f"percentile) (x{epss_factor(finding):.2f})."
        )
    elif v.cve_id:
        lines.append(f"No EPSS score published for {v.cve_id} (neutral).")

    lines.append(
        f"{'Direct' if finding.package.direct else 'Transitive'} dependency "
        f"(x{dependency_factor(finding):.2f})."
    )
    lines.append(
        f"Fix available in {v.fixed}." if v.has_fix else "No fixed version published."
    )
    lines.append(f"Final risk {finding.risk_score:.2f} vs baseline {finding.baseline_score:.2f}.")
    return lines


def score_findings(findings: list[Finding]) -> list[Finding]:
    """Score, explain, sort and rank a finding set in place."""
    for f in findings:
        f.risk_score = compute_risk(f)
        f.baseline_score = compute_baseline(f)
        f.rationale = explain(f)

    findings.sort(key=lambda f: (-f.risk_score, -f.vulnerability.cvss_score,
                                 f.vulnerability.vuln_id))
    for i, f in enumerate(findings, start=1):
        f.rank = i
    return findings


def rank_by_baseline(findings: list[Finding]) -> list[Finding]:
    """Ordering a conventional CVSS-only scanner would produce."""
    return sorted(
        findings,
        key=lambda f: (-f.vulnerability.cvss_score, f.vulnerability.vuln_id),
    )
