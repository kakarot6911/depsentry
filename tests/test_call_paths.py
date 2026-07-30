"""Tests for call-path location tracing (file:line evidence)."""

from __future__ import annotations

from depsentry.callgraph import build_call_graph, path_detail, render_path_detail
from depsentry.models import Reachability
from depsentry.pipeline import scan_project
from depsentry.report import _code_flow, to_sarif


class TestSourceLocations:
    def test_functions_record_their_file_and_line(self, unsafe_project):
        graph = build_call_graph(unsafe_project)
        node = graph.nodes["main.main"]
        assert node.filename == "main.py"
        assert node.lineno > 0

    def test_call_sites_record_line_numbers(self, unsafe_project):
        graph = build_call_graph(unsafe_project)
        node = graph.nodes["main._parse"]
        assert "yaml.load" in node.call_sites
        assert node.call_sites["yaml.load"] > node.lineno

    def test_first_call_site_wins(self, tmp_path):
        project = tmp_path / "repeated"
        project.mkdir()
        (project / "m.py").write_text(
            "import requests\n"
            "\n"
            "\n"
            "def main():\n"
            "    requests.get('a')\n"
            "    requests.get('b')\n"
        )
        graph = build_call_graph(project)
        assert graph.nodes["m.main"].call_sites["requests.get"] == 5


class TestPathDetail:
    def test_detail_has_one_entry_per_hop_plus_target(self, unsafe_project, test_db):
        result = scan_project(unsafe_project, db_path=test_db, epss=False)
        finding = next(
            f for f in result.findings if f.reachability is Reachability.REACHABLE
        )
        assert len(finding.path_detail) >= 2
        assert finding.path_detail[-1]["external"] is True

    def test_final_hop_is_the_vulnerable_symbol(self, unsafe_project, test_db):
        result = scan_project(unsafe_project, db_path=test_db, epss=False)
        finding = next(
            f for f in result.findings
            if f.vulnerability.vuln_id == "TEST-0001"
            and f.reachability is Reachability.REACHABLE
        )
        assert "yaml.load" in finding.path_detail[-1]["function"]

    def test_intermediate_hops_carry_call_lines(self, unsafe_project, test_db):
        result = scan_project(unsafe_project, db_path=test_db, epss=False)
        finding = next(
            f for f in result.findings if f.reachability is Reachability.REACHABLE
        )
        # Every non-final hop should know where it calls the next one.
        assert any(h.get("call_line") for h in finding.path_detail[:-1])

    def test_non_reachable_findings_have_no_detail(self, safe_project, test_db):
        result = scan_project(safe_project, db_path=test_db, epss=False)
        for finding in result.findings:
            if finding.reachability is not Reachability.REACHABLE:
                assert finding.path_detail == []

    def test_path_detail_on_unknown_node_marks_external(self, unsafe_project):
        graph = build_call_graph(unsafe_project)
        detail = path_detail(graph, "main.main", ("does.not.exist",), "yaml.load")
        assert detail[1]["external"] is True
        assert detail[1]["file"] == "<external>"


class TestRendering:
    def test_renders_as_indented_chain(self, unsafe_project, test_db):
        result = scan_project(unsafe_project, db_path=test_db, epss=False)
        finding = next(
            f for f in result.findings if f.reachability is Reachability.REACHABLE
        )
        text = render_path_detail(finding.path_detail)
        assert "[VULNERABLE]" in text
        assert "calls at line" in text
        assert "main.py" in text

    def test_empty_detail_renders_empty(self):
        assert render_path_detail([]) == ""


class TestSarifCodeFlows:
    def test_reachable_findings_get_code_flows(self, unsafe_project, test_db):
        result = scan_project(unsafe_project, db_path=test_db, epss=False)
        doc = to_sarif(result)
        with_flows = [r for r in doc["runs"][0]["results"] if "codeFlows" in r]
        assert with_flows

    def test_code_flow_shape_is_valid_sarif(self, unsafe_project, test_db):
        result = scan_project(unsafe_project, db_path=test_db, epss=False)
        finding = next(
            f for f in result.findings if f.reachability is Reachability.REACHABLE
        )
        flow = _code_flow(finding)

        assert "threadFlows" in flow
        locations = flow["threadFlows"][0]["locations"]
        assert locations
        for i, loc in enumerate(locations):
            physical = loc["location"]["physicalLocation"]
            assert physical["artifactLocation"]["uri"]
            assert isinstance(physical["region"]["startLine"], int)
            assert physical["region"]["startLine"] >= 1
            assert loc["nestingLevel"] == i
            assert loc["location"]["message"]["text"]

    def test_non_reachable_finding_yields_no_flow(self, safe_project, test_db):
        result = scan_project(safe_project, db_path=test_db, epss=False)
        finding = next(
            f for f in result.findings if f.reachability is not Reachability.REACHABLE
        )
        assert _code_flow(finding) is None

    def test_symbol_source_exposed_in_sarif_properties(self, safe_project, test_db):
        doc = to_sarif(scan_project(safe_project, db_path=test_db, epss=False))
        assert "symbolSource" in doc["runs"][0]["results"][0]["properties"]


class TestMarkdownIntegration:
    def test_markdown_includes_traced_path(self, unsafe_project, test_db):
        from depsentry.report import to_markdown

        result = scan_project(unsafe_project, db_path=test_db, epss=False)
        markdown = to_markdown(result)
        assert "Traced path with source locations" in markdown
