"""Local vulnerability database in OSV advisory shape, backed by SQLite.

DepSentry is designed to run offline (air-gapped CI, exam demo, no API keys), so
advisories live in a local SQLite file rather than being fetched from osv.dev.
The schema mirrors the OSV `affected.ranges` model closely enough that a real
OSV feed can be imported without changing any downstream code.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from .models import Package, Vulnerability

DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "vulndb.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    vuln_id          TEXT PRIMARY KEY,
    package          TEXT NOT NULL,
    ecosystem        TEXT NOT NULL DEFAULT 'PyPI',
    introduced       TEXT NOT NULL,
    fixed            TEXT,
    cvss_score       REAL NOT NULL,
    cvss_vector      TEXT NOT NULL DEFAULT '',
    summary          TEXT NOT NULL DEFAULT '',
    affected_symbols TEXT NOT NULL DEFAULT '[]',
    cwe              TEXT NOT NULL DEFAULT '[]',
    published        TEXT NOT NULL DEFAULT '',
    exploit_known    INTEGER NOT NULL DEFAULT 0,
    network_exposed  INTEGER NOT NULL DEFAULT 0,
    osv_id           TEXT,
    cve_id           TEXT,
    symbol_source    TEXT NOT NULL DEFAULT 'local'
);
CREATE INDEX IF NOT EXISTS idx_advisories_package ON advisories(package, ecosystem);
CREATE INDEX IF NOT EXISTS idx_advisories_osv ON advisories(osv_id);
"""

_VERSION_PART = re.compile(r"(\d+|[a-zA-Z]+)")


def parse_version(version: str) -> tuple:
    """Parse a version string into a comparable tuple.

    Deliberately simpler than full PEP 440, but it gets the two cases that
    actually decide advisory ranges right:

      * numeric segments compare numerically, so 1.9.0 < 1.10.0
      * a pre-release sorts BELOW its final release, so 1.0.0a1 < 1.0.0

    The second needs an explicit marker. Comparing raw token tuples would make
    1.0.0a1 the *longer* tuple and therefore the greater one, which is exactly
    backwards and would place pre-release users outside a range that affects them.

    Returns (release_quad, is_final, prerelease_tokens).
    """
    if not version or version == "*":
        return ((0, 0, 0, 0), 1, ())

    # Drop local version identifiers ("1.2.3+local") -- irrelevant to ranges.
    cleaned = version.strip().lstrip("v").split("+", 1)[0]

    release: list[int] = []
    prerelease: list[tuple[int, int | str]] = []
    in_prerelease = False

    for token in _VERSION_PART.findall(cleaned):
        if token.isdigit():
            if in_prerelease:
                prerelease.append((1, int(token)))
            else:
                release.append(int(token))
        else:
            # First alphabetic token starts the pre-release segment.
            in_prerelease = True
            prerelease.append((0, token.lower()))

    # Pad so 1.0 and 1.0.0 compare equal.
    quad = tuple((release + [0, 0, 0, 0])[:4])
    return (quad, 0 if in_prerelease else 1, tuple(prerelease))


def version_in_range(version: str, introduced: str, fixed: str | None) -> bool:
    """True when introduced <= version < fixed (fixed=None means unbounded)."""
    if version == "*":
        # Unpinned dependency: assume the worst, it may resolve into the range.
        return True

    v = parse_version(version)
    if v < parse_version(introduced):
        return False
    if fixed is not None and v >= parse_version(fixed):
        return False
    return True


class VulnerabilityDB:
    """Read/write access to the advisory store."""

    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created.

        SQLite has no `ADD COLUMN IF NOT EXISTS`, so existing columns are read
        first and only the missing ones are added. Keeps older advisory stores
        usable instead of forcing a re-seed.
        """
        have = {r[1] for r in self._conn.execute("PRAGMA table_info(advisories)")}
        for column, ddl in (
            ("osv_id", "TEXT"),
            ("cve_id", "TEXT"),
            ("symbol_source", "TEXT NOT NULL DEFAULT 'local'"),
        ):
            if column not in have:
                self._conn.execute(f"ALTER TABLE advisories ADD COLUMN {column} {ddl}")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "VulnerabilityDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def add(self, vuln: Vulnerability) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO advisories
                (vuln_id, package, ecosystem, introduced, fixed, cvss_score,
                 cvss_vector, summary, affected_symbols, cwe, published,
                 exploit_known, network_exposed, osv_id, cve_id, symbol_source)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                vuln.vuln_id,
                vuln.package,
                vuln.ecosystem,
                vuln.introduced,
                vuln.fixed,
                vuln.cvss_score,
                vuln.cvss_vector,
                vuln.summary,
                json.dumps(list(vuln.affected_symbols)),
                json.dumps(list(vuln.cwe)),
                vuln.published,
                int(vuln.exploit_known),
                int(vuln.network_exposed),
                vuln.osv_id,
                vuln.cve_id,
                vuln.symbol_source,
            ),
        )
        self._conn.commit()

    def add_many(self, vulns: list[Vulnerability]) -> int:
        for v in vulns:
            self.add(v)
        return len(vulns)

    @staticmethod
    def _row_to_vuln(row: sqlite3.Row) -> Vulnerability:
        return Vulnerability(
            vuln_id=row["vuln_id"],
            package=row["package"],
            ecosystem=row["ecosystem"],
            introduced=row["introduced"],
            fixed=row["fixed"],
            cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"],
            summary=row["summary"],
            affected_symbols=tuple(json.loads(row["affected_symbols"])),
            cwe=tuple(json.loads(row["cwe"])),
            published=row["published"],
            exploit_known=bool(row["exploit_known"]),
            network_exposed=bool(row["network_exposed"]),
            osv_id=row["osv_id"] if "osv_id" in row.keys() else None,
            cve_id=row["cve_id"] if "cve_id" in row.keys() else None,
            symbol_source=(row["symbol_source"] if "symbol_source" in row.keys() else None) or "local",
        )

    def all_advisories(self) -> list[Vulnerability]:
        rows = self._conn.execute("SELECT * FROM advisories ORDER BY vuln_id").fetchall()
        return [self._row_to_vuln(r) for r in rows]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) AS n FROM advisories").fetchone()["n"]

    def for_package(self, package: Package) -> list[Vulnerability]:
        """Advisories whose affected range contains this package version."""
        rows = self._conn.execute(
            "SELECT * FROM advisories WHERE package = ? AND ecosystem = ?",
            (package.name, package.ecosystem),
        ).fetchall()

        return [
            v
            for v in (self._row_to_vuln(r) for r in rows)
            if version_in_range(package.version, v.introduced, v.fixed)
        ]

    def match_sbom(self, packages: list[Package]) -> list[tuple[Package, Vulnerability]]:
        """Join every package against the advisory store."""
        matches: list[tuple[Package, Vulnerability]] = []
        for pkg in packages:
            for vuln in self.for_package(pkg):
                matches.append((pkg, vuln))
        return matches

    def import_osv_advisories(self, advisories: list[Vulnerability]) -> int:
        """Cache OSV-sourced advisories locally for offline reuse.

        Deduplicated on (osv_id, package, introduced) rather than vuln_id alone,
        because one advisory legitimately produces several rows when it declares
        multiple disjoint affected ranges. Returns the number newly inserted.
        """
        existing = {
            (row["osv_id"], row["package"], row["introduced"])
            for row in self._conn.execute(
                "SELECT osv_id, package, introduced FROM advisories WHERE osv_id IS NOT NULL"
            ).fetchall()
        }

        inserted = 0
        for vuln in advisories:
            key = (vuln.osv_id, vuln.package, vuln.introduced)
            if vuln.osv_id and key in existing:
                continue
            self.add(vuln)
            existing.add(key)
            inserted += 1
        return inserted

    def import_osv(self, records: list[dict]) -> int:
        """Import records in real OSV JSON format.

        Provided so the same pipeline can consume a live osv.dev export without
        code changes -- only the loader differs.
        """
        imported: list[Vulnerability] = []
        for rec in records:
            for affected in rec.get("affected", []):
                pkg = affected.get("package", {})
                for rng in affected.get("ranges", []):
                    introduced, fixed = "0", None
                    for event in rng.get("events", []):
                        if "introduced" in event:
                            introduced = event["introduced"]
                        if "fixed" in event:
                            fixed = event["fixed"]

                    severity = rec.get("severity", [{}])
                    vector = severity[0].get("score", "") if severity else ""
                    imported.append(
                        Vulnerability(
                            vuln_id=rec["id"],
                            package=pkg.get("name", ""),
                            ecosystem=pkg.get("ecosystem", "PyPI"),
                            introduced=introduced,
                            fixed=fixed,
                            cvss_score=float(
                                rec.get("database_specific", {}).get("cvss_score", 5.0)
                            ),
                            cvss_vector=vector,
                            summary=rec.get("summary", ""),
                            affected_symbols=tuple(
                                s.get("symbol", "")
                                for s in affected.get("ecosystem_specific", {}).get(
                                    "imports", []
                                )
                            ),
                            published=rec.get("published", ""),
                        )
                    )
        return self.add_many(imported)
