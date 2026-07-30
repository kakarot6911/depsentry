"""LLM-generated, code-specific remediation guidance for reachable findings.

Generic advice ("upgrade the package") is what every scanner already prints.
This module sends Claude the parts a generic tool doesn't have -- the advisory,
the traced call path, and the actual source at the call site -- and asks for the
fix *for this code*.

## Design constraints

**Optional, always.** No API key, no `anthropic` package, `--no-llm`, or an API
failure all degrade to `remediation_advice = None`. Nothing here can fail a
scan; every exception is caught and recorded.

**Bounded cost.** Only REACHABLE findings are considered, capped at
`--remediation-limit` (default 10), and responses are cached in SQLite keyed by
(advisory, symbol, call-path hash) so a re-scan of unchanged code costs nothing.

**Source is read, not executed** -- consistent with threat T5. Paths are
confined to the scanned project before any read.

## API notes

Model defaults to `claude-sonnet-5`. Two things that would otherwise be easy to
get wrong on this model family:

  * `temperature` / `top_p` / `top_k` are **rejected with a 400** -- output is
    steered by prompt alone.
  * Manual `thinking={"type": "enabled", "budget_tokens": N}` is removed; this
    uses adaptive thinking with a low effort setting, which suits a short,
    well-scoped generation task.

`stop_reason` is checked before reading content, because a refusal returns a
successful 200 with empty content and indexing `content[0]` would raise.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from .callgraph import render_path_detail
from .models import Finding

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_LIMIT = 10
MAX_TOKENS = 2048
SOURCE_WINDOW = 5

CACHE_PATH = Path(__file__).resolve().parents[2] / "data" / "remediation_cache.sqlite3"

_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS remediation (
    cache_key  TEXT PRIMARY KEY,
    advisory   TEXT NOT NULL,
    package    TEXT NOT NULL,
    model      TEXT NOT NULL,
    advice     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

PROMPT_TEMPLATE = """You are a security engineer reviewing a Python dependency \
vulnerability finding.

VULNERABILITY:
- Advisory: {advisory_id} — {summary}
- Affected symbol: {symbol}
- Package: {package}=={current_version}
- Fixed in: {fixed_version}
- CVSS: {cvss}{epss_line}

REACHABLE CALL PATH:
{call_path}

SOURCE CODE AT CALL SITE ({call_file}:{call_line}):
```python
{source_context}
```

Provide a concise, actionable remediation recommendation. Include:
1. The safest fix (usually upgrading to the fixed version)
2. If a safe API alternative exists (like yaml.safe_load instead of yaml.load), \
show the exact code change as a diff
3. Any breaking changes or caveats the developer should watch for
4. A one-line urgency summary

Be specific to THIS code, not generic advice. Keep it under 200 words."""


@dataclass
class RemediationStats:
    considered: int = 0
    generated: int = 0
    cache_hits: int = 0
    failures: list[str] = field(default_factory=list)

    def report(self) -> str:
        return (
            f"  considered  : {self.considered}\n"
            f"  generated   : {self.generated}\n"
            f"  cache hits  : {self.cache_hits}\n"
            f"  failures    : {len(self.failures)}"
        )


class _Cache:
    """SQLite-backed response cache. Never raises -- a broken cache just misses."""

    def __init__(self, path: str | Path = CACHE_PATH):
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.path))
            self._conn.executescript(_CACHE_SCHEMA)
            self._conn.commit()
        except sqlite3.Error:
            self._conn = None

    def get(self, key: str) -> str | None:
        if self._conn is None:
            return None
        try:
            row = self._conn.execute(
                "SELECT advice FROM remediation WHERE cache_key = ?", (key,)
            ).fetchone()
        except sqlite3.Error:
            return None
        return row[0] if row else None

    def put(self, key: str, finding: Finding, model: str, advice: str) -> None:
        if self._conn is None:
            return
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO remediation "
                "(cache_key, advisory, package, model, advice) VALUES (?,?,?,?,?)",
                (key, finding.vulnerability.vuln_id, finding.package.name, model, advice),
            )
            self._conn.commit()
        except sqlite3.Error:
            pass

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


def cache_key(finding: Finding, model: str) -> str:
    """Stable key over the inputs that would change the advice."""
    path_repr = "|".join(
        f"{h.get('function')}@{h.get('file')}:{h.get('call_line')}"
        for h in finding.path_detail
    )
    raw = " :: ".join([
        finding.vulnerability.vuln_id,
        ",".join(finding.vulnerability.affected_symbols),
        f"{finding.package.name}=={finding.package.version}",
        path_repr,
        model,
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


def read_source_window(
    project_root: str | Path, rel_file: str, line: int, radius: int = SOURCE_WINDOW
) -> str:
    """Read a window of source around a call site.

    The path is resolved and confined to the scanned project: a crafted
    `path_detail` entry must not be able to read arbitrary files, and nothing
    read here is ever executed.
    """
    try:
        root = Path(project_root).expanduser().resolve()
        target = (root / rel_file).resolve()
        target.relative_to(root)
        if not target.is_file():
            return ""
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return ""

    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    return "\n".join(f"{n + 1:>4}  {lines[n]}" for n in range(start, end))


def build_prompt(finding: Finding, project_root: str | Path) -> str:
    """Assemble the remediation prompt from a finding and its source context."""
    vuln = finding.vulnerability

    call_file, call_line = "", 0
    for hop in finding.path_detail:
        if hop.get("call_line") and not hop.get("external"):
            call_file, call_line = hop["file"], hop["call_line"]
    source = read_source_window(project_root, call_file, call_line) if call_file else ""

    epss_line = ""
    if finding.epss:
        epss_line = (
            f"\n- EPSS: {finding.epss.probability:.1%} probability of exploitation "
            f"in 30 days ({finding.epss.band})"
        )

    return PROMPT_TEMPLATE.format(
        advisory_id=vuln.cve_id or vuln.vuln_id,
        summary=vuln.summary or "(no summary provided)",
        symbol=", ".join(vuln.affected_symbols) or "(not specified)",
        package=finding.package.name,
        current_version=finding.package.version,
        # The spec's wording: say "unknown" rather than implying none exists.
        fixed_version=vuln.fixed or "unknown",
        cvss=vuln.cvss_score,
        epss_line=epss_line,
        call_path=render_path_detail(finding.path_detail) or "(no traced path)",
        call_file=call_file or "unknown",
        call_line=call_line or 0,
        source_context=source or "(source unavailable)",
    )


class RemediationEngine:
    """Generates remediation advice, degrading to a no-op when unavailable."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        model: str | None = None,
        cache_path: str | Path = CACHE_PATH,
        client=None,
    ):
        self.model = model or os.environ.get("DEPSENTRY_LLM_MODEL", DEFAULT_MODEL)
        self.stats = RemediationStats()
        self._cache = _Cache(cache_path)
        self._client = client
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

        if self._client is None and self._api_key:
            try:
                import anthropic

                self._client = anthropic.Anthropic(api_key=self._api_key)
            except ImportError:
                self._client = None

    @property
    def available(self) -> bool:
        """True when generation can actually be attempted."""
        return self._client is not None

    def _call_model(self, prompt: str) -> str | None:
        """One Messages API call. Returns None on any failure.

        No sampling parameters: `temperature`, `top_p` and `top_k` are rejected
        with a 400 on current Sonnet/Opus models. Output is steered by the
        prompt alone.
        """
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                # Short, well-scoped generation -- low effort is the right
                # cost/quality point and keeps latency down in a scan loop.
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # noqa: BLE001 - remediation must never fail a scan
            self.stats.failures.append(f"{type(exc).__name__}: {exc}")
            return None

        # A refusal returns HTTP 200 with empty content; indexing content[0]
        # without this check would raise.
        if getattr(response, "stop_reason", None) == "refusal":
            self.stats.failures.append("model declined to answer this finding")
            return None

        text = "".join(
            block.text
            for block in getattr(response, "content", [])
            if getattr(block, "type", None) == "text"
        ).strip()
        return text or None

    def generate_remediation(self, finding: Finding, project_root: str | Path) -> str | None:
        """Advice for one finding, or None if unavailable."""
        if not self.available:
            return None

        self.stats.considered += 1
        key = cache_key(finding, self.model)

        cached = self._cache.get(key)
        if cached is not None:
            self.stats.cache_hits += 1
            return cached

        advice = self._call_model(build_prompt(finding, project_root))
        if advice:
            self._cache.put(key, finding, self.model, advice)
            self.stats.generated += 1
        return advice

    def annotate(
        self, findings: list[Finding], *, project_root: str | Path, limit: int = DEFAULT_LIMIT
    ) -> int:
        """Attach advice to up to `limit` findings. Returns how many were set."""
        if not self.available:
            return 0

        attached = 0
        for finding in findings[:limit]:
            advice = self.generate_remediation(finding, project_root)
            if advice:
                finding.remediation_advice = advice
                attached += 1
        return attached

    def close(self) -> None:
        self._cache.close()
