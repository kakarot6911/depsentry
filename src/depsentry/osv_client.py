"""Live advisory retrieval from the OSV.dev API.

OSV (https://osv.dev) aggregates PYSEC, GHSA, CVE and ecosystem-native advisory
sources behind one schema. This client fetches real advisories for the packages
in an SBOM so DepSentry can be run against genuine CVEs rather than the local
synthetic corpus.

## The symbol-coverage problem (measured, not assumed)

DepSentry's reachability analysis needs to know *which function* an advisory
affects. OSV has a field for this -- `affected[].ecosystem_specific.imports[]`,
carrying `path` and `symbols`.

Sampling 171 real PyPI advisories across requests, urllib3, django, pyyaml,
jinja2, numpy and pillow found **zero** with symbol data. The Go ecosystem
populates it well (e.g. GO-2021-0053 lists
`["unmarshal.Generate", "unmarshal.field"]`), but the Python advisory sources
do not populate it at all.

Consequence: without mitigation, every live PyPI advisory resolves to UNKNOWN
and the reachability engine contributes nothing. Two things follow:

1. This client parses the OSV symbol fields correctly, so ecosystems that do
   populate them (Go) work today and PyPI works the moment upstream improves.
2. A local **symbol overlay** (`data/symbol_overlay.json`) maps advisory IDs and
   package/CWE patterns to known affected symbols, so live scanning stays
   useful for Python now. Overlay-sourced symbols are marked as such, never
   silently presented as upstream data.

`coverage_report()` surfaces the real numbers on every live scan, so the gap is
visible rather than hidden.
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .models import Package, Vulnerability

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

OVERLAY_PATH = Path(__file__).resolve().parents[2] / "data" / "symbol_overlay.json"

# Politeness delay between individual detail fetches. OSV needs no auth; this
# exists so a large SBOM does not hammer a free public service.
DETAIL_DELAY_S = 0.5
BATCH_SIZE = 100
TIMEOUT_S = 20

_CVSS_SCORE_RE = re.compile(r"CVSS:3\.[01]/", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class OSVUnavailable(RuntimeError):
    """Raised when OSV cannot be reached and no fallback was requested."""


@dataclass
class OSVStats:
    """Counters describing what a live fetch actually returned."""

    packages_queried: int = 0
    advisories_found: int = 0
    with_upstream_symbols: int = 0
    with_overlay_symbols: int = 0
    without_symbols: int = 0
    with_cvss: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def symbol_coverage(self) -> float:
        """Fraction of advisories that carry usable symbol data."""
        if not self.advisories_found:
            return 0.0
        traceable = self.with_upstream_symbols + self.with_overlay_symbols
        return traceable / self.advisories_found

    def report(self) -> str:
        lines = [
            f"  packages queried    : {self.packages_queried}",
            f"  advisories found    : {self.advisories_found}",
            f"  with CVSS severity  : {self.with_cvss}",
            f"  symbols (upstream)  : {self.with_upstream_symbols}",
            f"  symbols (overlay)   : {self.with_overlay_symbols}",
            f"  no symbol data      : {self.without_symbols}",
            f"  symbol coverage     : {self.symbol_coverage:.0%}",
        ]
        if self.without_symbols:
            lines.append(
                f"  note: {self.without_symbols} advisory/ies lack symbol data and "
                "will be scored UNKNOWN (not assumed safe)."
            )
        if self.errors:
            lines.append(f"  errors              : {len(self.errors)}")
        return "\n".join(lines)


def _ssl_context() -> ssl.SSLContext:
    """Build a verifying SSL context, preferring certifi's CA bundle.

    Python installed from python.org on macOS often ships without a usable
    system trust store, which makes every HTTPS call fail with
    CERTIFICATE_VERIFY_FAILED. Falling back to certifi fixes that without ever
    disabling verification.
    """
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def cvss_score_from_vector(vector: str) -> float | None:
    """Derive a numeric base score from a CVSS v3 vector string.

    OSV supplies the vector, not the score. Rather than pull in a CVSS library
    for one calculation, this implements the v3.1 base-score formula directly
    (spec: FIRST CVSS v3.1 section 8.1).
    """
    if not vector or not _CVSS_SCORE_RE.search(vector):
        return None

    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, _, value = part.partition(":")
            metrics[key.upper()] = value.upper()

    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr_map = (
            {"N": 0.85, "L": 0.68, "H": 0.50}
            if scope_changed
            else {"N": 0.85, "L": 0.62, "H": 0.27}
        )
        pr = pr_map[metrics["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = cia[metrics["C"]], cia[metrics["I"]], cia[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
    # CVSS rounds up to one decimal place.
    return float(int(raw * 10 + 0.99999) / 10)


def extract_symbols(affected: dict) -> tuple[str, ...]:
    """Pull affected symbol names out of one OSV `affected` entry.

    Handles every shape observed in the wild plus the ones the schema permits:
      * ecosystem_specific.imports[].symbols  (Go vulndb -- the populated one)
      * ecosystem_specific.affected_functions
      * database_specific.affected_functions
    """
    symbols: list[str] = []

    for container in (
        affected.get("ecosystem_specific") or {},
        affected.get("database_specific") or {},
    ):
        if not isinstance(container, dict):
            continue

        for imp in container.get("imports") or []:
            if not isinstance(imp, dict):
                continue
            path = imp.get("path", "")
            for sym in imp.get("symbols") or []:
                # Go symbols are package-relative; qualify with the import path
                # so they match the same way Python dotted names do.
                symbols.append(f"{path}.{sym}" if path and "." not in sym else sym)

        for key in ("affected_functions", "functions", "symbols"):
            for sym in container.get(key) or []:
                if isinstance(sym, str):
                    symbols.append(sym)

    # Preserve order, drop duplicates.
    return tuple(dict.fromkeys(s for s in symbols if s))


def _best_severity(record: dict) -> tuple[float, str]:
    """Return (score, vector) using the highest-confidence CVSS entry present."""
    best_score, best_vector = 0.0, ""
    for sev in record.get("severity") or []:
        vector = sev.get("score", "") or ""
        if sev.get("type", "").upper().startswith("CVSS"):
            score = cvss_score_from_vector(vector)
            if score is not None and score >= best_score:
                best_score, best_vector = score, vector
    return best_score, best_vector


def _ranges(affected: dict) -> list[tuple[str, str | None]]:
    """Extract (introduced, fixed) pairs from an OSV affected entry."""
    out: list[tuple[str, str | None]] = []
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER", None):
            continue
        introduced, fixed = "0", None
        for event in rng.get("events") or []:
            if "introduced" in event:
                introduced = event["introduced"] or "0"
            if "fixed" in event:
                fixed = event["fixed"]
            if "last_affected" in event and fixed is None:
                # last_affected is inclusive; the exclusive bound is unknown, so
                # leave fixed unset rather than guessing a wrong upper bound.
                pass
        out.append((introduced, fixed))
    if not out and affected.get("versions"):
        out.append(("0", None))
    return out


class SymbolOverlay:
    """Local advisory-ID -> symbols map, compensating for upstream gaps.

    Entries are curated and explicitly marked, so an overlay-sourced symbol is
    never presented as though OSV supplied it.
    """

    def __init__(self, path: str | Path = OVERLAY_PATH):
        self.path = Path(path)
        self._by_id: dict[str, list[str]] = {}
        self._by_package: dict[str, list[str]] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        self._by_id = {k.upper(): v for k, v in (doc.get("by_advisory") or {}).items()}
        self._by_package = {
            k.lower(): v for k, v in (doc.get("by_package") or {}).items()
        }

    def lookup(
        self,
        vuln_id: str,
        aliases: tuple[str, ...],
        package: str,
        *,
        use_heuristic: bool = False,
    ) -> tuple[str, ...]:
        """Resolve symbols for an advisory.

        The advisory-ID map is authoritative and always consulted. The
        package-level map is a heuristic -- it attributes a library's dangerous
        API surface to *any* advisory on that library, which is sometimes
        wrong -- so it is only used when explicitly enabled.
        """
        for key in (vuln_id, *aliases):
            hit = self._by_id.get(key.upper())
            if hit:
                return tuple(hit)
        if use_heuristic:
            return tuple(self._by_package.get(package.lower().replace("_", "-"), ()))
        return ()

    def __len__(self) -> int:
        return len(self._by_id) + len(self._by_package)


class OSVClient:
    """Queries OSV.dev and converts responses into DepSentry Vulnerabilities."""

    def __init__(
        self,
        *,
        timeout: float = TIMEOUT_S,
        detail_delay: float = DETAIL_DELAY_S,
        overlay: SymbolOverlay | None = None,
        use_heuristic: bool = False,
        opener=None,
    ):
        self.timeout = timeout
        self.detail_delay = detail_delay
        self.overlay = overlay if overlay is not None else SymbolOverlay()
        self.use_heuristic = use_heuristic
        self.stats = OSVStats()
        # Injectable for tests; production path uses urllib with a verified context.
        self._opener = opener or self._default_opener
        self._ctx = _ssl_context()

    # -- transport ------------------------------------------------------

    def _default_opener(self, url: str, payload: dict | None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DepSentry/1.1 (+https://github.com/example/depsentry)",
            },
            method="POST" if data is not None else "GET",
        )
        with urllib.request.urlopen(request, timeout=self.timeout, context=self._ctx) as fh:
            return json.load(fh)

    def _call(self, url: str, payload: dict | None = None) -> dict:
        try:
            return self._opener(url, payload)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            raise OSVUnavailable(f"{type(exc).__name__}: {exc}") from exc

    # -- queries --------------------------------------------------------

    def query_package(self, package: Package) -> list[dict]:
        """Raw OSV records affecting one package version."""
        payload = {
            "package": {"name": package.name, "ecosystem": package.ecosystem},
            "version": package.version,
        }
        return self._call(OSV_QUERY, payload).get("vulns") or []

    def query_batch(self, packages: list[Package]) -> dict[str, list[str]]:
        """Batch query. Returns {purl: [vuln_id, ...]}.

        The batch endpoint returns IDs only, so full records still need
        fetching -- but one round trip instead of N is a large saving on a
        realistic SBOM.
        """
        results: dict[str, list[str]] = {}

        for start in range(0, len(packages), BATCH_SIZE):
            chunk = packages[start : start + BATCH_SIZE]
            payload = {
                "queries": [
                    {
                        "package": {"name": p.name, "ecosystem": p.ecosystem},
                        "version": p.version,
                    }
                    for p in chunk
                ]
            }
            response = self._call(OSV_QUERYBATCH, payload)
            for pkg, entry in zip(chunk, response.get("results") or []):
                ids = [v["id"] for v in (entry.get("vulns") or []) if v.get("id")]
                if ids:
                    results[pkg.purl] = ids
        return results

    def fetch_vuln(self, vuln_id: str) -> dict:
        """Full advisory record by ID."""
        return self._call(OSV_VULN + vuln_id, None)

    # -- conversion -----------------------------------------------------

    def to_vulnerabilities(self, record: dict, package: Package) -> list[Vulnerability]:
        """Convert one OSV record into DepSentry Vulnerabilities.

        One record can yield several, since an advisory may declare multiple
        disjoint affected ranges.
        """
        vuln_id = record.get("id", "")
        if not vuln_id:
            return []

        aliases = tuple(record.get("aliases") or [])
        cvss_score, cvss_vector = _best_severity(record)
        summary = (record.get("summary") or record.get("details") or "").strip()
        if len(summary) > 400:
            summary = summary[:397] + "..."

        # Prefer a CVE alias as the canonical ID -- EPSS is keyed on CVE.
        cve = next((a for a in aliases if _CVE_RE.match(a)), None)

        out: list[Vulnerability] = []
        for affected in record.get("affected") or []:
            pkg_name = (affected.get("package") or {}).get("name", package.name)
            if pkg_name.lower().replace("_", "-") != package.name.lower().replace("_", "-"):
                continue

            symbols = extract_symbols(affected)
            source = "upstream"
            if not symbols:
                symbols = self.overlay.lookup(
                    vuln_id, aliases, package.name, use_heuristic=self.use_heuristic
                )
                source = "overlay" if symbols else "none"

            if source == "upstream":
                self.stats.with_upstream_symbols += 1
            elif source == "overlay":
                self.stats.with_overlay_symbols += 1
            else:
                self.stats.without_symbols += 1
            if cvss_score:
                self.stats.with_cvss += 1

            cwes = tuple(
                c for c in ((record.get("database_specific") or {}).get("cwe_ids") or [])
            )

            for introduced, fixed in _ranges(affected) or [("0", None)]:
                out.append(
                    Vulnerability(
                        vuln_id=vuln_id,
                        package=package.name,
                        ecosystem=package.ecosystem,
                        introduced=introduced,
                        fixed=fixed,
                        # OSV omits severity on many records; 5.0 (MEDIUM) is a
                        # neutral placeholder rather than a silent 0.0, which
                        # would suppress the finding entirely.
                        cvss_score=cvss_score or 5.0,
                        cvss_vector=cvss_vector,
                        summary=summary or f"{vuln_id} affecting {package.name}",
                        affected_symbols=symbols,
                        cwe=cwes,
                        published=record.get("published", ""),
                        osv_id=vuln_id,
                        cve_id=cve,
                        symbol_source=source,
                    )
                )
        return out

    # -- top level ------------------------------------------------------

    def advisories_for(self, packages: list[Package]) -> list[tuple[Package, Vulnerability]]:
        """Fetch and convert advisories for every package in an SBOM."""
        self.stats = OSVStats(packages_queried=len(packages))
        by_purl = {p.purl: p for p in packages}

        try:
            batch = self.query_batch(packages)
        except OSVUnavailable:
            raise

        # De-duplicate detail fetches: one advisory often affects many packages.
        wanted: dict[str, list[Package]] = {}
        for purl, ids in batch.items():
            for vid in ids:
                wanted.setdefault(vid, []).append(by_purl[purl])

        matches: list[tuple[Package, Vulnerability]] = []
        for i, (vuln_id, pkgs) in enumerate(sorted(wanted.items())):
            if i and self.detail_delay:
                time.sleep(self.detail_delay)
            try:
                record = self.fetch_vuln(vuln_id)
            except OSVUnavailable as exc:
                self.stats.errors.append(f"{vuln_id}: {exc}")
                continue

            self.stats.advisories_found += 1
            for pkg in pkgs:
                for vuln in self.to_vulnerabilities(record, pkg):
                    matches.append((pkg, vuln))

        return matches

    def coverage_report(self) -> str:
        return self.stats.report()
