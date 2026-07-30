"""Tests for the OSV.dev client.

Every network call is mocked -- pytest must never touch the real API.
"""

from __future__ import annotations

import json

import pytest

from depsentry.models import Package, Vulnerability
from depsentry.osv_client import (
    OSVClient,
    OSVUnavailable,
    SymbolOverlay,
    cvss_score_from_vector,
    extract_symbols,
)
from depsentry.vulndb import VulnerabilityDB


# --- fixtures --------------------------------------------------------------

GHSA_NO_SYMBOLS = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2024-12345"],
    "summary": "Header leak on cross-origin redirect.",
    "published": "2024-05-01T00:00:00Z",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
    ],
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}],
            "ecosystem_specific": {},
            "database_specific": {"source": "https://example/advisory.yaml"},
        }
    ],
}

GO_WITH_SYMBOLS = {
    "id": "GO-2021-0053",
    "aliases": ["CVE-2021-3121"],
    "summary": "Unmarshal panic.",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.3.2"}]}],
            "ecosystem_specific": {
                "imports": [{"path": "mypkg.unmarshal", "symbols": ["Generate", "field"]}]
            },
        }
    ],
}

REQUESTS_PKG = Package(name="requests", version="2.28.0")


def make_client(responses: dict, **kw) -> OSVClient:
    """Client whose transport returns canned payloads keyed by URL substring."""

    def opener(url: str, payload):
        for fragment, response in responses.items():
            if fragment in url:
                return response
        raise AssertionError(f"unexpected URL: {url}")

    kw.setdefault("detail_delay", 0)
    return OSVClient(opener=opener, **kw)


# --- CVSS ------------------------------------------------------------------

class TestCVSSDerivation:
    """OSV supplies vectors, not scores, so the formula must be right."""

    @pytest.mark.parametrize("vector,expected", [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ])
    def test_matches_published_reference_scores(self, vector, expected):
        assert cvss_score_from_vector(vector) == expected

    def test_rejects_non_cvss3(self):
        assert cvss_score_from_vector("CVSS:2.0/AV:N") is None
        assert cvss_score_from_vector("") is None

    def test_malformed_vector_returns_none(self):
        assert cvss_score_from_vector("CVSS:3.1/AV:Z/AC:L") is None


# --- symbol extraction -----------------------------------------------------

class TestSymbolExtraction:
    def test_go_style_imports_are_qualified_with_path(self):
        symbols = extract_symbols(GO_WITH_SYMBOLS["affected"][0])
        assert "mypkg.unmarshal.Generate" in symbols
        assert "mypkg.unmarshal.field" in symbols

    def test_affected_functions_field(self):
        assert extract_symbols(
            {"database_specific": {"affected_functions": ["pkg.danger"]}}
        ) == ("pkg.danger",)

    def test_empty_when_absent(self):
        assert extract_symbols(GHSA_NO_SYMBOLS["affected"][0]) == ()

    def test_handles_null_containers(self):
        assert extract_symbols({"ecosystem_specific": None, "database_specific": None}) == ()


# --- conversion ------------------------------------------------------------

class TestConversion:
    def test_advisory_with_symbols_is_traceable(self):
        client = make_client({})
        vulns = client.to_vulnerabilities(GO_WITH_SYMBOLS, REQUESTS_PKG)
        assert vulns and vulns[0].affected_symbols
        assert vulns[0].symbol_source == "upstream"
        assert vulns[0].is_traceable

    def test_advisory_without_symbols_yields_no_symbols(self):
        """The real-world PyPI case: no symbols -> UNKNOWN downstream."""
        client = make_client({})
        vulns = client.to_vulnerabilities(GHSA_NO_SYMBOLS, REQUESTS_PKG)
        assert vulns
        assert vulns[0].affected_symbols == ()
        assert vulns[0].symbol_source == "none"
        assert not vulns[0].is_traceable

    def test_cve_alias_is_captured_for_epss(self):
        client = make_client({})
        v = client.to_vulnerabilities(GHSA_NO_SYMBOLS, REQUESTS_PKG)[0]
        assert v.cve_id == "CVE-2024-12345"
        assert v.osv_id == "GHSA-aaaa-bbbb-cccc"

    def test_cvss_derived_from_vector(self):
        client = make_client({})
        assert client.to_vulnerabilities(GHSA_NO_SYMBOLS, REQUESTS_PKG)[0].cvss_score == 7.5

    def test_missing_severity_gets_neutral_placeholder(self):
        record = {**GHSA_NO_SYMBOLS, "severity": []}
        client = make_client({})
        v = client.to_vulnerabilities(record, REQUESTS_PKG)[0]
        # 5.0 keeps the finding alive; 0.0 would silently suppress it.
        assert v.cvss_score == 5.0

    def test_ranges_are_extracted(self):
        client = make_client({})
        v = client.to_vulnerabilities(GHSA_NO_SYMBOLS, REQUESTS_PKG)[0]
        assert (v.introduced, v.fixed) == ("0", "2.32.0")

    def test_mismatched_package_is_skipped(self):
        client = make_client({})
        assert client.to_vulnerabilities(GHSA_NO_SYMBOLS, Package(name="flask", version="1.0")) == []


# --- overlay ---------------------------------------------------------------

class TestSymbolOverlay:
    def test_package_heuristic_is_opt_in(self, tmp_path):
        path = tmp_path / "overlay.json"
        path.write_text(json.dumps({
            "by_advisory": {},
            "by_package": {"pyyaml": ["yaml.load"]},
        }))
        overlay = SymbolOverlay(path)
        assert overlay.lookup("GHSA-x", (), "pyyaml") == ()
        assert overlay.lookup("GHSA-x", (), "pyyaml", use_heuristic=True) == ("yaml.load",)

    def test_advisory_map_is_authoritative_and_always_used(self, tmp_path):
        path = tmp_path / "overlay.json"
        path.write_text(json.dumps({
            "by_advisory": {"GHSA-AAAA-BBBB-CCCC": ["requests.get"]},
            "by_package": {"requests": ["requests.post"]},
        }))
        overlay = SymbolOverlay(path)
        assert overlay.lookup("GHSA-aaaa-bbbb-cccc", (), "requests") == ("requests.get",)

    def test_alias_lookup(self, tmp_path):
        path = tmp_path / "overlay.json"
        path.write_text(json.dumps({"by_advisory": {"CVE-2024-12345": ["x.y"]}, "by_package": {}}))
        overlay = SymbolOverlay(path)
        assert overlay.lookup("GHSA-zzz", ("CVE-2024-12345",), "requests") == ("x.y",)

    def test_overlay_symbols_are_marked_as_overlay(self, tmp_path):
        path = tmp_path / "overlay.json"
        path.write_text(json.dumps({
            "by_advisory": {"GHSA-AAAA-BBBB-CCCC": ["requests.get"]}, "by_package": {},
        }))
        client = make_client({}, overlay=SymbolOverlay(path))
        v = client.to_vulnerabilities(GHSA_NO_SYMBOLS, REQUESTS_PKG)[0]
        assert v.symbol_source == "overlay"

    def test_missing_overlay_file_is_not_fatal(self, tmp_path):
        assert len(SymbolOverlay(tmp_path / "nope.json")) == 0

    def test_corrupt_overlay_file_is_not_fatal(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        assert len(SymbolOverlay(path)) == 0


# --- queries ---------------------------------------------------------------

class TestQueries:
    def test_batch_query_construction(self):
        captured = {}

        def opener(url, payload):
            captured["url"] = url
            captured["payload"] = payload
            return {"results": [{"vulns": [{"id": "GHSA-1"}]}, {"vulns": []}]}

        client = OSVClient(opener=opener, detail_delay=0)
        packages = [Package(name="requests", version="2.28.0"),
                    Package(name="flask", version="2.0.0")]
        result = client.query_batch(packages)

        assert "querybatch" in captured["url"]
        assert len(captured["payload"]["queries"]) == 2
        assert captured["payload"]["queries"][0]["package"]["name"] == "requests"
        assert result == {"pkg:pypi/requests@2.28.0": ["GHSA-1"]}

    def test_batch_chunks_at_100(self):
        calls = []

        def opener(url, payload):
            calls.append(len(payload["queries"]))
            return {"results": [{"vulns": []} for _ in payload["queries"]]}

        client = OSVClient(opener=opener, detail_delay=0)
        client.query_batch([Package(name=f"p{i}", version="1.0") for i in range(250)])
        assert calls == [100, 100, 50]

    def test_advisories_for_end_to_end(self):
        client = make_client({
            "querybatch": {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]},
            "/vulns/": GHSA_NO_SYMBOLS,
        })
        matches = client.advisories_for([REQUESTS_PKG])
        assert len(matches) == 1
        assert matches[0][1].osv_id == "GHSA-aaaa-bbbb-cccc"
        assert client.stats.advisories_found == 1
        assert client.stats.without_symbols == 1

    def test_network_failure_raises_osv_unavailable(self):
        def opener(url, payload):
            raise OSError("network down")

        with pytest.raises(OSVUnavailable):
            OSVClient(opener=opener, detail_delay=0).advisories_for([REQUESTS_PKG])


# --- coverage reporting ----------------------------------------------------

class TestCoverageReporting:
    def test_coverage_is_zero_when_no_symbols(self):
        client = make_client({
            "querybatch": {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]},
            "/vulns/": GHSA_NO_SYMBOLS,
        })
        client.advisories_for([REQUESTS_PKG])
        assert client.stats.symbol_coverage == 0.0
        assert "UNKNOWN" in client.coverage_report()

    def test_coverage_is_one_when_upstream_symbols_present(self):
        client = make_client({
            "querybatch": {"results": [{"vulns": [{"id": "GO-2021-0053"}]}]},
            "/vulns/": GO_WITH_SYMBOLS,
        })
        client.advisories_for([REQUESTS_PKG])
        assert client.stats.symbol_coverage == 1.0


# --- caching / dedup -------------------------------------------------------

class TestCaching:
    def _vuln(self, vuln_id="GHSA-1", introduced="0"):
        return Vulnerability(
            vuln_id=vuln_id, package="requests", ecosystem="PyPI",
            introduced=introduced, fixed="2.32.0", cvss_score=7.5,
            cvss_vector="", summary="s", osv_id=vuln_id, symbol_source="none",
        )

    def test_same_advisory_twice_does_not_duplicate(self, tmp_path):
        db_path = tmp_path / "cache.sqlite3"
        with VulnerabilityDB(db_path) as db:
            assert db.import_osv_advisories([self._vuln()]) == 1
            assert db.import_osv_advisories([self._vuln()]) == 0
            assert db.count() == 1

    def test_distinct_ranges_of_one_advisory_are_kept(self, tmp_path):
        with VulnerabilityDB(tmp_path / "c.sqlite3") as db:
            db.import_osv_advisories([
                self._vuln(introduced="0"),
                self._vuln(vuln_id="GHSA-2", introduced="2.0"),
            ])
            assert db.count() == 2

    def test_provenance_survives_a_roundtrip(self, tmp_path):
        with VulnerabilityDB(tmp_path / "c.sqlite3") as db:
            db.import_osv_advisories([self._vuln()])
            restored = db.all_advisories()[0]
        assert restored.osv_id == "GHSA-1"
        assert restored.symbol_source == "none"
