"""EPSS (Exploit Prediction Scoring System) lookups from FIRST.org.

EPSS answers the question CVSS deliberately does not: *how likely is this to
actually be exploited?* It publishes a daily-updated probability (0-1) that a
CVE will be exploited in the wild within the next 30 days.

Combining it with reachability is the point. Reachability says "an attacker
could get here from your code"; EPSS says "attackers are actually doing this".
A finding that is both reachable and high-EPSS is the one to fix this morning.

Only CVE identifiers are scored. GHSA-only advisories are skipped -- silently in
the return value, visibly in `stats`.

API: https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2  (no auth required)
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .models import EPSSScore

EPSS_API = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
TIMEOUT_S = 20

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class EPSSUnavailable(RuntimeError):
    """Raised when the EPSS API cannot be reached."""


def is_cve(identifier: str) -> bool:
    return bool(identifier and _CVE_RE.match(identifier))


@dataclass
class EPSSStats:
    requested: int = 0
    cve_queried: int = 0
    skipped_non_cve: int = 0
    scores_found: int = 0
    unscored: list[str] = field(default_factory=list)

    def report(self) -> str:
        return (
            f"  identifiers in      : {self.requested}\n"
            f"  CVEs queried        : {self.cve_queried}\n"
            f"  skipped (non-CVE)   : {self.skipped_non_cve}\n"
            f"  scores returned     : {self.scores_found}\n"
            f"  CVEs with no score  : {len(self.unscored)}"
        )


def _ssl_context() -> ssl.SSLContext:
    """Verifying context, preferring certifi (python.org macOS builds lack a store)."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


class EPSSClient:
    """Batched EPSS lookups with in-process caching.

    EPSS refreshes once daily, so caching for the lifetime of a scan costs
    nothing in accuracy and avoids re-querying an advisory that affects several
    packages.
    """

    def __init__(self, *, timeout: float = TIMEOUT_S, opener=None):
        self.timeout = timeout
        self.stats = EPSSStats()
        self._cache: dict[str, EPSSScore] = {}
        self._opener = opener or self._default_opener
        self._ctx = _ssl_context()

    def _default_opener(self, url: str) -> dict:
        request = urllib.request.Request(
            url, headers={"User-Agent": "DepSentry/1.1"}, method="GET"
        )
        with urllib.request.urlopen(request, timeout=self.timeout, context=self._ctx) as fh:
            return json.load(fh)

    def _call(self, url: str) -> dict:
        try:
            return self._opener(url)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            raise EPSSUnavailable(f"{type(exc).__name__}: {exc}") from exc

    @staticmethod
    def parse_response(payload: dict) -> dict[str, EPSSScore]:
        """Convert an EPSS API payload into {cve_id: EPSSScore}.

        The API returns probabilities as strings ("0.999990000"), so they are
        coerced and clamped; a malformed row is skipped rather than crashing a
        scan over a scoring nicety.
        """
        out: dict[str, EPSSScore] = {}
        for row in payload.get("data") or []:
            cve = row.get("cve")
            if not cve:
                continue
            try:
                probability = float(row.get("epss", 0.0))
                percentile = float(row.get("percentile", 0.0))
            except (TypeError, ValueError):
                continue
            out[cve.upper()] = EPSSScore(
                cve_id=cve.upper(),
                probability=min(max(probability, 0.0), 1.0),
                percentile=min(max(percentile, 0.0), 1.0),
            )
        return out

    def scores_for(self, identifiers: list[str]) -> dict[str, EPSSScore]:
        """Fetch EPSS scores for a list of advisory identifiers.

        Non-CVE identifiers (GHSA, PYSEC, GO) are filtered out -- they have no
        EPSS score by construction. Results are cached in-process.
        """
        self.stats = EPSSStats(requested=len(identifiers))

        cves = sorted({i.upper() for i in identifiers if is_cve(i)})
        self.stats.skipped_non_cve = len(identifiers) - len(
            [i for i in identifiers if is_cve(i)]
        )

        pending = [c for c in cves if c not in self._cache]
        self.stats.cve_queried = len(cves)

        for start in range(0, len(pending), BATCH_SIZE):
            chunk = pending[start : start + BATCH_SIZE]
            url = f"{EPSS_API}?{urllib.parse.urlencode({'cve': ','.join(chunk)})}"
            self._cache.update(self.parse_response(self._call(url)))

        found = {c: self._cache[c] for c in cves if c in self._cache}
        self.stats.scores_found = len(found)
        self.stats.unscored = [c for c in cves if c not in self._cache]
        return found

    def score_for(self, cve_id: str) -> EPSSScore | None:
        """Single-CVE convenience wrapper."""
        return self.scores_for([cve_id]).get(cve_id.upper())
