"""Tests for SBOM generation, advisory matching, risk fusion, integrity, pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depsentry.integrity import AuditLog, hmac_sign, sign_sbom, verify_sbom
from depsentry.models import (
    Finding, Package, Reachability, SBOM, Severity, Vulnerability,
)
from depsentry.pipeline import scan_project
from depsentry.report import to_markdown, to_sarif
from depsentry.risk import compute_risk, score_findings
from depsentry.sbom import generate_sbom, parse_requirements
from depsentry.vulndb import VulnerabilityDB, parse_version, version_in_range


def _vuln(**kw) -> Vulnerability:
    base = dict(
        vuln_id="V-1", package="requests", ecosystem="PyPI", introduced="0",
        fixed="2.32.0", cvss_score=7.5, cvss_vector="", summary="s",
        affected_symbols=("requests.get",),
    )
    base.update(kw)
    return Vulnerability(**base)


class TestVersionRanges:
    @pytest.mark.parametrize("version,introduced,fixed,expected", [
        ("2.28.0", "0", "2.32.0", True),
        ("2.32.0", "0", "2.32.0", False),   # fixed is exclusive
        ("2.32.1", "0", "2.32.0", False),
        ("1.0.0", "2.0.0", None, False),
        ("3.0.0", "2.0.0", None, True),     # unbounded upper range
        ("*", "0", "1.0.0", True),          # unpinned: assume vulnerable
    ])
    def test_ranges(self, version, introduced, fixed, expected):
        assert version_in_range(version, introduced, fixed) is expected

    def test_ordering(self):
        assert parse_version("1.9.0") < parse_version("1.10.0")
        assert parse_version("2.0.0") > parse_version("1.99.99")

    def test_prerelease_sorts_below_release(self):
        assert parse_version("1.0.0a1") < parse_version("1.0.0")

    def test_local_version_is_ignored(self):
        assert parse_version("1.2.3+local") == parse_version("1.2.3")


class TestSeverity:
    @pytest.mark.parametrize("score,band", [
        (0.0, Severity.NONE), (3.9, Severity.LOW), (5.0, Severity.MEDIUM),
        (7.0, Severity.HIGH), (9.8, Severity.CRITICAL),
    ])
    def test_cvss_bands(self, score, band):
        assert Severity.from_cvss(score) is band


class TestSBOM:
    def test_exact_pin_beats_installed_version(self, tmp_path):
        """A `==` pin is what deploys, so it must win over the local install."""
        project = tmp_path / "pinned"
        project.mkdir()
        (project / "requirements.txt").write_text("requests==2.28.0\n")
        (project / "main.py").write_text("def main():\n    return 1\n")

        sbom = generate_sbom(project)
        requests_pkg = next(p for p in sbom.packages if p.name == "requests")
        assert requests_pkg.version == "2.28.0"

    def test_requirements_parsing(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text(
            "# comment\n"
            "requests==2.28.0\n"
            "flask>=2.0  # inline comment\n"
            "urllib3[secure]==1.26.5\n"
            "pytest ; python_version < '3.12'\n"
            "-r other.txt\n"
            "\n"
        )
        pins = parse_requirements(path)
        assert pins["requests"] == ("==", "2.28.0")
        assert pins["flask"] == (">=", "2.0")
        assert pins["urllib3"] == ("==", "1.26.5")
        assert "-r" not in pins

    def test_cyclonedx_shape(self, tmp_path):
        sbom = SBOM(project="p", packages=[Package(name="requests", version="2.28.0")])
        doc = sbom.to_cyclonedx()
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["components"][0]["purl"] == "pkg:pypi/requests@2.28.0"

    def test_canonical_bytes_ignore_timestamp(self):
        a = SBOM(project="p", packages=[Package(name="x", version="1.0")],
                 generated_at="2026-01-01T00:00:00Z")
        b = SBOM(project="p", packages=[Package(name="x", version="1.0")],
                 generated_at="2026-07-30T12:00:00Z")
        assert a.canonical_bytes() == b.canonical_bytes()


class TestAdvisoryMatching:
    def test_matches_only_in_range(self, test_db):
        with VulnerabilityDB(test_db) as db:
            vulnerable = db.for_package(Package(name="requests", version="2.28.0"))
            patched = db.for_package(Package(name="requests", version="2.32.0"))
        assert {v.vuln_id for v in vulnerable} >= {"TEST-0002"}
        assert "TEST-0002" not in {v.vuln_id for v in patched}

    def test_osv_import(self, tmp_path):
        with VulnerabilityDB(tmp_path / "osv.sqlite3") as db:
            n = db.import_osv([{
                "id": "OSV-1", "summary": "test",
                "affected": [{
                    "package": {"name": "flask", "ecosystem": "PyPI"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
                }],
                "database_specific": {"cvss_score": 8.1},
            }])
            assert n == 1
            assert db.for_package(Package(name="flask", version="1.0.0"))


class TestRiskFusion:
    def test_reachability_dominates_severity(self):
        """An unreachable CRITICAL must score below a reachable MEDIUM."""
        pkg = Package(name="p", version="1.0")
        critical_unreachable = Finding(
            vulnerability=_vuln(cvss_score=9.8), package=pkg,
            reachability=Reachability.UNREACHABLE,
        )
        medium_reachable = Finding(
            vulnerability=_vuln(cvss_score=5.0), package=pkg,
            reachability=Reachability.REACHABLE,
        )
        assert compute_risk(critical_unreachable) < compute_risk(medium_reachable)

    def test_score_is_clamped_to_cvss_scale(self):
        f = Finding(
            vulnerability=_vuln(cvss_score=10.0, exploit_known=True,
                                network_exposed=True),
            package=Package(name="p", version="1.0", direct=True),
            reachability=Reachability.REACHABLE,
        )
        assert 0.0 <= compute_risk(f) <= 10.0

    def test_ranking_and_rationale_are_populated(self):
        pkg = Package(name="p", version="1.0")
        findings = [
            Finding(vulnerability=_vuln(vuln_id="A", cvss_score=9.8), package=pkg,
                    reachability=Reachability.UNREACHABLE),
            Finding(vulnerability=_vuln(vuln_id="B", cvss_score=6.0), package=pkg,
                    reachability=Reachability.REACHABLE),
        ]
        score_findings(findings)
        assert findings[0].vulnerability.vuln_id == "B"
        assert findings[0].rank == 1
        assert findings[0].rationale

    def test_unreachable_is_not_actionable(self):
        f = Finding(
            vulnerability=_vuln(cvss_score=9.8),
            package=Package(name="p", version="1.0"),
            reachability=Reachability.UNREACHABLE,
        )
        score_findings([f])
        assert not f.actionable


class TestIntegrity:
    def test_hmac_roundtrip(self):
        sbom = SBOM(project="p", packages=[Package(name="x", version="1.0")])
        sign_sbom(sbom, b"secret")
        assert verify_sbom(sbom, b"secret")

    def test_wrong_key_fails(self):
        sbom = SBOM(project="p", packages=[Package(name="x", version="1.0")])
        sign_sbom(sbom, b"secret")
        assert not verify_sbom(sbom, b"wrong")

    def test_tampered_sbom_fails_verification(self):
        sbom = SBOM(project="p", packages=[Package(name="x", version="1.0")])
        sign_sbom(sbom, b"secret")
        sbom.packages.append(Package(name="evil", version="6.6.6"))
        assert not verify_sbom(sbom, b"secret")

    def test_unsigned_sbom_does_not_verify(self):
        assert not verify_sbom(SBOM(project="p", packages=[]), b"secret")

    def test_hmac_is_deterministic(self):
        assert hmac_sign(b"data", b"k") == hmac_sign(b"data", b"k")


class TestAuditLog:
    def test_chain_verifies(self, tmp_path):
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(3):
            log.append("scan", {"n": i})
        ok, message = log.verify()
        assert ok, message

    def test_tampering_is_detected(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("scan", {"n": 0})
        log.append("scan", {"n": 1})

        lines = path.read_text().splitlines()
        record = json.loads(lines[0])
        record["payload"]["n"] = 999          # edit history, keep the hash
        lines[0] = json.dumps(record, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")

        ok, message = log.verify()
        assert not ok
        assert "modified" in message or "broken" in message

    def test_deletion_is_detected(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        for i in range(3):
            log.append("scan", {"n": i})

        lines = path.read_text().splitlines()
        path.write_text("\n".join([lines[0], lines[2]]) + "\n")  # drop the middle
        ok, _ = log.verify()
        assert not ok

    def test_empty_log_verifies(self, tmp_path):
        ok, _ = AuditLog(tmp_path / "nothing.jsonl").verify()
        assert ok


class TestPipeline:
    def test_safe_project_suppresses_critical(self, safe_project, test_db):
        result = scan_project(safe_project, db_path=test_db)
        yaml_findings = [
            f for f in result.findings if f.vulnerability.vuln_id == "TEST-0001"
        ]
        assert yaml_findings
        assert yaml_findings[0].reachability is Reachability.UNREACHABLE
        assert not yaml_findings[0].actionable

    def test_unsafe_project_surfaces_critical(self, unsafe_project, test_db):
        result = scan_project(unsafe_project, db_path=test_db)
        yaml_findings = [
            f for f in result.findings if f.vulnerability.vuln_id == "TEST-0001"
        ]
        assert yaml_findings[0].reachability is Reachability.REACHABLE
        assert yaml_findings[0].actionable

    def test_noise_reduction_is_a_fraction(self, safe_project, test_db):
        result = scan_project(safe_project, db_path=test_db)
        assert 0.0 <= result.noise_reduction() <= 1.0

    def test_missing_directory_raises(self, tmp_path, test_db):
        with pytest.raises(NotADirectoryError):
            scan_project(tmp_path / "nope", db_path=test_db)

    def test_audit_log_written(self, safe_project, test_db, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        scan_project(safe_project, db_path=test_db, audit_log_path=log_path)
        assert len(AuditLog(log_path).entries()) == 1


class TestReporting:
    def test_markdown_lists_suppressed_findings(self, safe_project, test_db):
        md = to_markdown(scan_project(safe_project, db_path=test_db))
        assert "# DepSentry Report" in md
        assert "Suppressed findings" in md

    def test_sarif_is_wellformed(self, unsafe_project, test_db):
        doc = to_sarif(scan_project(unsafe_project, db_path=test_db))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "DepSentry"
        assert doc["runs"][0]["results"]

    def test_sarif_downgrades_unreachable_to_note(self, safe_project, test_db):
        doc = to_sarif(scan_project(safe_project, db_path=test_db))
        yaml_results = [
            r for r in doc["runs"][0]["results"] if r["ruleId"] == "TEST-0001"
        ]
        assert yaml_results[0]["level"] == "note"
