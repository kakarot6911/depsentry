"""Tests for EPSS integration. All network calls are mocked."""

from __future__ import annotations

import pytest

from depsentry.epss_client import EPSSClient, EPSSUnavailable, is_cve
from depsentry.models import (
    EPSSScore, Finding, Package, Reachability, Vulnerability,
)
from depsentry.risk import (
    EPSS_ABSENT, EPSS_CRITICAL, EPSS_HIGH, EPSS_LOW, EPSS_MODERATE,
    compute_risk, epss_factor, score_findings,
)

RESPONSE = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.999990000", "percentile": "1.000000000"},
        {"cve": "CVE-2020-14343", "epss": "0.059840000", "percentile": "0.925660000"},
    ],
}


def make_client(response=RESPONSE):
    return EPSSClient(opener=lambda url: response)


def make_finding(cvss=7.0, reach=Reachability.REACHABLE, epss_p=None,
                 cve="CVE-2024-0001", direct=True):
    vuln = Vulnerability(
        vuln_id="V-1", package="p", ecosystem="PyPI", introduced="0", fixed="9.9",
        cvss_score=cvss, cvss_vector="", summary="s",
        affected_symbols=("p.f",), cve_id=cve,
    )
    finding = Finding(
        vulnerability=vuln,
        package=Package(name="p", version="1.0", direct=direct),
        reachability=reach,
    )
    if epss_p is not None:
        finding.epss = EPSSScore(cve, epss_p, 0.9)
    return finding


class TestIdentifierFiltering:
    @pytest.mark.parametrize("ident,expected", [
        ("CVE-2021-44228", True),
        ("cve-2021-44228", True),
        ("GHSA-aaaa-bbbb-cccc", False),
        ("PYSEC-2020-176", False),
        ("GO-2021-0053", False),
        ("", False),
    ])
    def test_is_cve(self, ident, expected):
        assert is_cve(ident) is expected

    def test_non_cve_ids_are_skipped_not_queried(self):
        calls = []

        def opener(url):
            calls.append(url)
            return {"data": []}

        client = EPSSClient(opener=opener)
        client.scores_for(["GHSA-aaaa-bbbb-cccc", "PYSEC-2020-176"])
        assert calls == [], "GHSA/PYSEC ids must never reach the EPSS API"
        assert client.stats.skipped_non_cve == 2


class TestResponseParsing:
    def test_parses_string_probabilities(self):
        scores = EPSSClient.parse_response(RESPONSE)
        assert scores["CVE-2021-44228"].probability == pytest.approx(0.99999)
        assert scores["CVE-2021-44228"].percentile == pytest.approx(1.0)

    def test_malformed_row_is_skipped_not_fatal(self):
        scores = EPSSClient.parse_response(
            {"data": [{"cve": "CVE-1-1", "epss": "not-a-number"},
                      {"cve": "CVE-2021-44228", "epss": "0.5", "percentile": "0.9"}]}
        )
        assert "CVE-2021-44228" in scores
        assert len(scores) == 1

    def test_row_without_cve_is_skipped(self):
        assert EPSSClient.parse_response({"data": [{"epss": "0.5"}]}) == {}

    def test_probabilities_are_clamped(self):
        scores = EPSSClient.parse_response(
            {"data": [{"cve": "CVE-1-1234", "epss": "5.0", "percentile": "-1"}]}
        )
        assert scores["CVE-1-1234"].probability == 1.0
        assert scores["CVE-1-1234"].percentile == 0.0


class TestBatching:
    def test_batches_at_100(self):
        sizes = []

        def opener(url):
            sizes.append(url.count("%2C") + 1)  # urlencoded commas
            return {"data": []}

        client = EPSSClient(opener=opener)
        client.scores_for([f"CVE-2024-{i:05d}" for i in range(250)])
        assert sizes == [100, 100, 50]

    def test_results_are_cached_across_calls(self):
        calls = []

        def opener(url):
            calls.append(url)
            return RESPONSE

        client = EPSSClient(opener=opener)
        client.scores_for(["CVE-2021-44228"])
        client.scores_for(["CVE-2021-44228"])
        assert len(calls) == 1, "second lookup should hit the cache"

    def test_network_failure_raises(self):
        def opener(url):
            raise OSError("dns failure")

        with pytest.raises(EPSSUnavailable):
            EPSSClient(opener=opener).scores_for(["CVE-2021-44228"])

    def test_unscored_cves_are_recorded(self):
        client = EPSSClient(opener=lambda url: {"data": []})
        assert client.scores_for(["CVE-2024-99999"]) == {}
        assert client.stats.unscored == ["CVE-2024-99999"]


class TestRiskFactorTiers:
    @pytest.mark.parametrize("probability,expected", [
        (0.99, EPSS_CRITICAL),
        (0.70, EPSS_CRITICAL),
        (0.69, EPSS_HIGH),
        (0.30, EPSS_HIGH),
        (0.29, EPSS_MODERATE),
        (0.10, EPSS_MODERATE),
        (0.09, EPSS_LOW),
        (0.0, EPSS_LOW),
    ])
    def test_each_tier(self, probability, expected):
        assert epss_factor(make_finding(epss_p=probability)) == expected

    def test_absent_epss_is_neutral(self):
        assert epss_factor(make_finding(epss_p=None)) == EPSS_ABSENT

    def test_absent_epss_leaves_score_unchanged(self):
        """Backward compatibility: v1.0 behaviour when EPSS is off."""
        finding = make_finding(cvss=7.5, epss_p=None)
        expected = 7.5 * 1.0 * 0.95 * 1.10 * 1.05  # no network/exploit flags
        assert compute_risk(finding) == pytest.approx(expected)


class TestRankingBehaviour:
    def test_high_epss_outranks_low_epss_at_equal_cvss(self):
        high = make_finding(cvss=7.0, epss_p=0.95)
        low = make_finding(cvss=7.0, epss_p=0.02)
        assert compute_risk(high) > compute_risk(low)

    def test_epss_never_overrides_reachability(self):
        """The central invariant: an unreachable finding stays below a reachable one."""
        unreachable_max_epss = make_finding(
            cvss=10.0, reach=Reachability.UNREACHABLE, epss_p=0.999
        )
        reachable_min_epss = make_finding(
            cvss=5.0, reach=Reachability.REACHABLE, epss_p=0.001
        )
        assert compute_risk(unreachable_max_epss) < compute_risk(reachable_min_epss)

    def test_ranking_places_high_epss_first(self):
        findings = [
            make_finding(cvss=7.0, epss_p=0.01),
            make_finding(cvss=7.0, epss_p=0.99),
        ]
        score_findings(findings)
        assert findings[0].epss.probability == pytest.approx(0.99)
        assert findings[0].rank == 1

    def test_score_stays_within_cvss_scale(self):
        finding = make_finding(cvss=10.0, epss_p=0.999)
        finding.vulnerability = Vulnerability(
            vuln_id="V", package="p", ecosystem="PyPI", introduced="0", fixed="1",
            cvss_score=10.0, cvss_vector="", summary="s",
            exploit_known=True, network_exposed=True, cve_id="CVE-2024-0001",
        )
        assert 0.0 <= compute_risk(finding) <= 10.0


class TestRationale:
    def test_epss_appears_in_rationale(self):
        finding = make_finding(epss_p=0.85)
        score_findings([finding])
        assert any("EPSS" in line for line in finding.rationale)

    def test_missing_epss_for_a_cve_is_noted(self):
        finding = make_finding(epss_p=None, cve="CVE-2024-0001")
        score_findings([finding])
        assert any("No EPSS score" in line for line in finding.rationale)
