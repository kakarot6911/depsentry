"""Tests for OpenVEX generation."""

from __future__ import annotations

import json

import pytest

from depsentry.models import (
    CallPath, EPSSScore, Finding, Package, Reachability, SBOM, ScanResult, Vulnerability,
)
from depsentry.vex import (
    JUSTIFICATION_NOT_IN_PATH, OPENVEX_CONTEXT, STATUS_AFFECTED,
    STATUS_NOT_AFFECTED, STATUS_UNDER_INVESTIGATION,
    build_vex, render_vex, statement_for, vex_summary,
)


def make_finding(reach, *, symbols=("yaml.load",), fixed="6.0.2",
                 cve="CVE-2024-1111", with_path=False, epss=None):
    vuln = Vulnerability(
        vuln_id="GHSA-test", package="pyyaml", ecosystem="PyPI",
        introduced="0", fixed=fixed, cvss_score=9.8, cvss_vector="",
        summary="Arbitrary code execution via the unsafe loader.",
        affected_symbols=symbols, cve_id=cve, osv_id="GHSA-test",
        symbol_source="upstream",
    )
    finding = Finding(
        vulnerability=vuln,
        package=Package(name="pyyaml", version="5.4.1"),
        reachability=reach,
    )
    if with_path:
        finding.call_paths = [
            CallPath(entrypoint="main.main", steps=("config.load",), target_symbol="yaml.load")
        ]
    if epss is not None:
        finding.epss = EPSSScore(cve, epss, 0.95)
    return finding


def make_result(findings):
    return ScanResult(
        project="demo",
        sbom=SBOM(project="demo", packages=[Package(name="pyyaml", version="5.4.1")]),
        findings=findings,
    )


class TestStatusMapping:
    def test_reachable_is_affected(self):
        s = statement_for(make_finding(Reachability.REACHABLE, with_path=True))
        assert s["status"] == STATUS_AFFECTED
        assert s["action_statement"]
        assert "6.0.2" in s["action_statement"]

    def test_unreachable_is_not_affected_with_justification(self):
        s = statement_for(make_finding(Reachability.UNREACHABLE))
        assert s["status"] == STATUS_NOT_AFFECTED
        assert s["justification"] == JUSTIFICATION_NOT_IN_PATH

    def test_unknown_is_under_investigation(self):
        s = statement_for(make_finding(Reachability.UNKNOWN, symbols=()))
        assert s["status"] == STATUS_UNDER_INVESTIGATION
        assert "does not name a specific affected symbol" in s["impact_statement"]

    def test_potentially_reachable_is_under_investigation(self):
        s = statement_for(make_finding(Reachability.POTENTIALLY_REACHABLE))
        assert s["status"] == STATUS_UNDER_INVESTIGATION
        assert "dynamic dispatch" in s["impact_statement"]

    def test_under_investigation_carries_no_justification(self):
        """OpenVEX only permits justification on not_affected."""
        for reach in (Reachability.UNKNOWN, Reachability.POTENTIALLY_REACHABLE):
            assert "justification" not in statement_for(make_finding(reach, symbols=()))

    def test_affected_carries_no_justification(self):
        s = statement_for(make_finding(Reachability.REACHABLE))
        assert "justification" not in s


class TestEvidence:
    def test_reachable_impact_statement_contains_call_path(self):
        s = statement_for(make_finding(Reachability.REACHABLE, with_path=True))
        assert "main.main -> config.load -> yaml.load" in s["impact_statement"]

    def test_unreachable_impact_names_the_symbol(self):
        s = statement_for(make_finding(Reachability.UNREACHABLE))
        assert "yaml.load" in s["impact_statement"]
        assert "never executed" in s["impact_statement"]

    def test_no_fixed_version_changes_the_action(self):
        s = statement_for(make_finding(Reachability.REACHABLE, fixed=None))
        assert "No fixed version" in s["action_statement"]

    def test_high_epss_is_called_out_in_the_action(self):
        s = statement_for(make_finding(Reachability.REACHABLE, epss=0.85))
        assert "EPSS" in s["action_statement"]

    def test_low_epss_is_not_called_out(self):
        s = statement_for(make_finding(Reachability.REACHABLE, epss=0.01))
        assert "EPSS" not in s["action_statement"]


class TestDocumentStructure:
    def test_required_openvex_fields(self):
        doc = build_vex(make_result([make_finding(Reachability.REACHABLE)]))
        for key in ("@context", "@id", "author", "role", "timestamp", "version", "statements"):
            assert key in doc, f"missing required OpenVEX field: {key}"
        assert doc["@context"] == OPENVEX_CONTEXT
        assert doc["role"] == "tool"

    def test_output_is_valid_json(self):
        doc = json.loads(render_vex(make_result([make_finding(Reachability.UNREACHABLE)])))
        assert doc["statements"][0]["status"] == STATUS_NOT_AFFECTED

    def test_document_ids_are_unique(self):
        result = make_result([make_finding(Reachability.REACHABLE)])
        ids = {build_vex(result)["@id"] for _ in range(20)}
        assert len(ids) == 20

    def test_purl_format(self):
        s = statement_for(make_finding(Reachability.REACHABLE))
        assert s["products"][0]["@id"] == "pkg:pypi/pyyaml@5.4.1"
        assert s["products"][0]["subcomponents"][0]["@id"] == "pkg:pypi/pyyaml@5.4.1"

    def test_cve_gets_nvd_url_osv_id_gets_osv_url(self):
        cve_stmt = statement_for(make_finding(Reachability.REACHABLE, cve="CVE-2024-1111"))
        assert "nvd.nist.gov" in cve_stmt["vulnerability"]["@id"]

        ghsa_stmt = statement_for(make_finding(Reachability.REACHABLE, cve=None))
        assert "osv.dev" in ghsa_stmt["vulnerability"]["@id"]

    def test_depsentry_extras_are_namespaced(self):
        s = statement_for(make_finding(Reachability.REACHABLE, with_path=True))
        assert "depsentry:analysis" in s
        assert s["depsentry:analysis"]["reachability"] == "REACHABLE"

    def test_statement_count_matches_findings(self):
        findings = [
            make_finding(Reachability.REACHABLE),
            make_finding(Reachability.UNREACHABLE),
            make_finding(Reachability.UNKNOWN, symbols=()),
        ]
        assert len(build_vex(make_result(findings))["statements"]) == 3


class TestMixedVerdicts:
    def test_summary_counts(self):
        result = make_result([
            make_finding(Reachability.REACHABLE),
            make_finding(Reachability.UNREACHABLE),
            make_finding(Reachability.UNREACHABLE),
            make_finding(Reachability.UNKNOWN, symbols=()),
            make_finding(Reachability.POTENTIALLY_REACHABLE),
        ])
        counts = vex_summary(result)
        assert counts[STATUS_AFFECTED] == 1
        assert counts[STATUS_NOT_AFFECTED] == 2
        assert counts[STATUS_UNDER_INVESTIGATION] == 2

    def test_empty_scan_produces_empty_statements(self):
        doc = build_vex(make_result([]))
        assert doc["statements"] == []
        assert doc["@context"] == OPENVEX_CONTEXT


class TestIntegrationWithReports:
    def test_write_reports_emits_vex(self, safe_project, test_db, tmp_path):
        from depsentry.pipeline import scan_project
        from depsentry.report import write_reports

        result = scan_project(safe_project, db_path=test_db, epss=False)
        paths = write_reports(result, tmp_path)
        assert "vex" in paths
        assert paths["vex"].name == "vex.json"
        doc = json.loads(paths["vex"].read_text())
        assert doc["@context"] == OPENVEX_CONTEXT

    def test_vex_can_be_disabled(self, safe_project, test_db, tmp_path):
        from depsentry.pipeline import scan_project
        from depsentry.report import write_reports

        result = scan_project(safe_project, db_path=test_db, epss=False)
        paths = write_reports(result, tmp_path, vex=False)
        assert "vex" not in paths
        assert not (tmp_path / "vex.json").exists()
