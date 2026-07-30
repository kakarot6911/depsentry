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

    @property
    def severity(self) -> Severity:
        return Severity.from_cvss(self.cvss_score)

    @property
    def has_fix(self) -> bool:
        return self.fixed is not None


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
