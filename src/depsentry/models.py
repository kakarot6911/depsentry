"""Core data models for DepSentry.

Everything that moves between pipeline stages is one of these dataclasses.
Keeping them dependency-free (stdlib only) means the models can be imported by
the CLI, the API and the dashboard without dragging in sklearn or streamlit.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """CVSS v3 qualitative severity bands."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score <= 0.0:
            return cls.NONE
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


class Reachability(str, Enum):
    """Result of the static reachability analysis for a single vulnerability.

    UNREACHABLE is the interesting one: the dependency is installed and the CVE
    is real, but no path exists from application code to the affected symbol.
    """

    REACHABLE = "REACHABLE"
    POTENTIALLY_REACHABLE = "POTENTIALLY_REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"

    @property
    def weight(self) -> float:
        """Multiplier applied to the base CVSS score during risk fusion."""
        return {
            Reachability.REACHABLE: 1.0,
            Reachability.POTENTIALLY_REACHABLE: 0.6,
            Reachability.UNKNOWN: 0.4,
            Reachability.UNREACHABLE: 0.1,
        }[self]


@dataclass(frozen=True)
class Package:
    """One resolved dependency in the dependency graph."""

    name: str
    version: str
    ecosystem: str = "PyPI"
    direct: bool = True
    parents: tuple[str, ...] = ()
    license: str | None = None
    sha256: str | None = None

    @property
    def purl(self) -> str:
        """Package URL identifier, the CycloneDX/SPDX interchange key."""
        return f"pkg:{self.ecosystem.lower()}/{self.name}@{self.version}"

    @property
    def depth(self) -> int:
        """0 for direct dependencies, 1+ for transitive ones."""
        return 0 if self.direct else len(self.parents)


@dataclass(frozen=True)
class Vulnerability:
    """An advisory affecting a package version range.

    `affected_symbols` is what makes reachability analysis possible: advisories
    that name the vulnerable function let us ask whether that function is ever
    called, instead of only asking whether the package is installed.
    """

    vuln_id: str
    package: str
    ecosystem: str
    introduced: str
    fixed: str | None
    cvss_score: float
    cvss_vector: str
    summary: str
    affected_symbols: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    published: str = ""
    exploit_known: bool = False
    network_exposed: bool = False

    # -- provenance, populated when the advisory came from OSV.dev ---------
    osv_id: str | None = None
    """Upstream OSV identifier (GHSA-…, PYSEC-…, GO-…) when live-sourced."""

    cve_id: str | None = None
    """CVE alias, if the advisory has one. EPSS is keyed on CVE, so this is
    what the EPSS client looks up; GHSA-only advisories have no EPSS score."""

    symbol_source: str = "local"
    """Where `affected_symbols` came from: 'upstream' (OSV itself), 'overlay'
    (local curated map), 'none' (no symbol data available), or 'local' (the
    bundled synthetic corpus). Kept explicit so an overlay-sourced symbol is
    never mistaken for upstream data."""

    @property
    def severity(self) -> Severity:
        return Severity.from_cvss(self.cvss_score)

    @property
    def has_fix(self) -> bool:
        return self.fixed is not None

    @property
    def is_traceable(self) -> bool:
        """True when reachability analysis can say anything about this advisory."""
        return bool(self.affected_symbols)


@dataclass(frozen=True)
class EPSSScore:
    """Exploit Prediction Scoring System result for one CVE.

    EPSS estimates the probability a vulnerability will be exploited in the wild
    within the next 30 days. It answers a different question from CVSS: CVSS
    says how bad exploitation *would* be, EPSS says how likely it *is*.

    Only CVE identifiers have EPSS scores. GHSA-only advisories have none.
    """

    cve_id: str
    probability: float
    """0-1. Chance of observed exploitation in the next 30 days."""

    percentile: float
    """0-1. Rank relative to all scored CVEs."""

    @property
    def band(self) -> str:
        """Qualitative band, used for display and for the risk multiplier."""
        if self.probability >= 0.7:
            return "CRITICAL"
        if self.probability >= 0.3:
            return "HIGH"
        if self.probability >= 0.1:
            return "MODERATE"
        return "LOW"


@dataclass
class CallPath:
    """A concrete chain of calls from an entrypoint to a vulnerable symbol.

    This is the evidence shown to a developer. Without it, a "reachable"
    verdict is unfalsifiable and reviewers rightly distrust it.
    """

    entrypoint: str
    steps: tuple[str, ...]
    target_symbol: str
    confidence: float = 1.0
    detail: list[dict] = field(default_factory=list)
    """Per-hop file/line locations; populated by the reachability analyzer."""

    def render(self) -> str:
        return " -> ".join([self.entrypoint, *self.steps, self.target_symbol])


@dataclass
class Finding:
    """A vulnerability joined to the package instance it affects, plus verdict."""

    vulnerability: Vulnerability
    package: Package
    reachability: Reachability = Reachability.UNKNOWN
    call_paths: list[CallPath] = field(default_factory=list)
    risk_score: float = 0.0
    baseline_score: float = 0.0
    rank: int = 0
    rationale: list[str] = field(default_factory=list)
    epss: "EPSSScore | None" = None
    """Exploit probability, when the advisory has a CVE alias and EPSS is on."""

    remediation_advice: str | None = None
    """LLM-generated, code-specific fix guidance. None unless enabled."""

    path_detail: list[dict] = field(default_factory=list)
    """Call path enriched with file/line locations; see callgraph.path_detail()."""

    @property
    def finding_id(self) -> str:
        raw = f"{self.vulnerability.vuln_id}|{self.package.purl}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def actionable(self) -> bool:
        """Would DepSentry put this in front of a developer today?"""
        return self.reachability in (
            Reachability.REACHABLE,
            Reachability.POTENTIALLY_REACHABLE,
        ) and self.risk_score >= 4.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_id": self.vulnerability.vuln_id,
            "package": self.package.name,
            "version": self.package.version,
            "purl": self.package.purl,
            "direct": self.package.direct,
            "cvss": self.vulnerability.cvss_score,
            "severity": self.vulnerability.severity.value,
            "reachability": self.reachability.value,
            "risk_score": round(self.risk_score, 2),
            "baseline_score": round(self.baseline_score, 2),
            "rank": self.rank,
            "actionable": self.actionable,
            "fixed_in": self.vulnerability.fixed,
            "summary": self.vulnerability.summary,
            "call_paths": [p.render() for p in self.call_paths],
            "rationale": self.rationale,
            "cve_id": self.vulnerability.cve_id,
            "osv_id": self.vulnerability.osv_id,
            "symbol_source": self.vulnerability.symbol_source,
            "epss": (
                {
                    "probability": round(self.epss.probability, 6),
                    "percentile": round(self.epss.percentile, 6),
                    "band": self.epss.band,
                }
                if self.epss
                else None
            ),
            "remediation_advice": self.remediation_advice,
            "path_detail": self.path_detail,
        }


@dataclass
class SBOM:
    """Software Bill of Materials for one scanned project."""

    project: str
    packages: list[Package]
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    spec_version: str = "CycloneDX-1.5-subset"
    signature: str | None = None

    def to_cyclonedx(self) -> dict[str, Any]:
        """Emit a CycloneDX-shaped document.

        This is a faithful subset, not the full spec: enough for interchange and
        for signature verification, without vendoring the whole schema.
        """
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": self.generated_at,
                "component": {"type": "application", "name": self.project},
                "tools": [{"vendor": "DepSentry", "name": "depsentry", "version": "1.0.0"}],
            },
            "components": [
                {
                    "type": "library",
                    "name": p.name,
                    "version": p.version,
                    "purl": p.purl,
                    "scope": "required",
                    "licenses": ([{"license": {"id": p.license}}] if p.license else []),
                    "hashes": ([{"alg": "SHA-256", "content": p.sha256}] if p.sha256 else []),
                    "properties": [
                        {"name": "depsentry:direct", "value": str(p.direct).lower()},
                        {"name": "depsentry:parents", "value": ",".join(p.parents)},
                    ],
                }
                for p in self.packages
            ],
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic serialisation used as the signing payload.

        The timestamp is excluded so that re-generating an SBOM for unchanged
        dependencies produces an identical digest.
        """
        doc = self.to_cyclonedx()
        doc["metadata"].pop("timestamp", None)
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class ScanResult:
    """Everything one full scan produces."""

    project: str
    sbom: SBOM
    findings: list[Finding]
    entrypoints: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def actionable_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.actionable]

    def noise_reduction(self) -> float:
        """Fraction of raw findings suppressed as non-actionable.

        This is the headline metric: how much of the alert pile a developer no
        longer has to read.
        """
        if not self.findings:
            return 0.0
        return 1.0 - (len(self.actionable_findings) / len(self.findings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "scanned_at": self.scanned_at,
            "entrypoints": self.entrypoints,
            "package_count": len(self.sbom.packages),
            "total_findings": len(self.findings),
            "actionable_findings": len(self.actionable_findings),
            "noise_reduction": round(self.noise_reduction(), 4),
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }
