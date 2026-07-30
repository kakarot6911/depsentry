"""Tests for the reachability engine -- the project's core claim.

If any test here regresses, the headline result is invalid.
"""

from __future__ import annotations

from pathlib import Path

from depsentry.callgraph import build_call_graph, reachable_external_symbols
from depsentry.models import Reachability
from depsentry.reachability import ReachabilityAnalyzer, import_names_for
from depsentry.vulndb import VulnerabilityDB


def _analyzer(project: Path) -> ReachabilityAnalyzer:
    return ReachabilityAnalyzer(build_call_graph(project))


def _advisory(db_path: Path, vuln_id: str):
    with VulnerabilityDB(db_path) as db:
        return next(a for a in db.all_advisories() if a.vuln_id == vuln_id)


class TestSymbolDiscrimination:
    """safe_load must never be mistaken for load."""

    def test_safe_loader_does_not_match_unsafe_advisory(self, safe_project, test_db):
        verdict = _analyzer(safe_project).analyze(_advisory(test_db, "TEST-0001"))
        assert verdict.status is Reachability.UNREACHABLE
        assert "no call path reaches" in verdict.reason

    def test_unsafe_loader_is_reachable(self, unsafe_project, test_db):
        verdict = _analyzer(unsafe_project).analyze(_advisory(test_db, "TEST-0001"))
        assert verdict.status is Reachability.REACHABLE
        assert verdict.call_paths, "a REACHABLE verdict must carry evidence"
        assert "yaml.load" in verdict.call_paths[0].render()

    def test_call_path_starts_at_an_entrypoint(self, unsafe_project, test_db):
        verdict = _analyzer(unsafe_project).analyze(_advisory(test_db, "TEST-0001"))
        graph = build_call_graph(unsafe_project)
        assert verdict.call_paths[0].entrypoint in graph.entrypoints


class TestVerdictRules:
    def test_package_not_imported_is_unreachable(self, tmp_path, test_db):
        project = tmp_path / "bare"
        project.mkdir()
        (project / "requirements.txt").write_text("pyyaml==5.4.1\n")
        (project / "main.py").write_text("def main():\n    return 1\n")

        verdict = _analyzer(project).analyze(_advisory(test_db, "TEST-0001"))
        assert verdict.status is Reachability.UNREACHABLE
        assert "not imported" in verdict.reason

    def test_advisory_without_symbols_is_unknown_not_safe(self, safe_project, test_db):
        """No symbol data means we cannot prove safety, so never claim it."""
        verdict = _analyzer(safe_project).analyze(_advisory(test_db, "TEST-0003"))
        assert verdict.status is Reachability.UNKNOWN
        assert verdict.status is not Reachability.UNREACHABLE

    def test_dynamic_dispatch_prevents_unreachable_claim(self, dynamic_project, test_db):
        verdict = _analyzer(dynamic_project).analyze(_advisory(test_db, "TEST-0001"))
        assert verdict.status is Reachability.POTENTIALLY_REACHABLE
        assert "dynamic dispatch" in verdict.reason

    def test_unknown_outranks_unreachable_in_weight(self):
        assert Reachability.UNKNOWN.weight > Reachability.UNREACHABLE.weight
        assert Reachability.REACHABLE.weight == 1.0


class TestCallGraph:
    def test_decorated_route_is_an_entrypoint(self, tmp_path):
        project = tmp_path / "web"
        project.mkdir()
        (project / "app.py").write_text(
            "import flask\n"
            "app = flask.Flask(__name__)\n"
            "\n"
            "\n"
            "@app.route('/x')\n"
            "def handler():\n"
            "    return 'ok'\n"
        )
        assert "app.handler" in build_call_graph(project).entrypoints

    def test_transitive_call_chain_is_traced(self, tmp_path):
        project = tmp_path / "chain"
        project.mkdir()
        (project / "m.py").write_text(
            "import requests\n"
            "\n"
            "\n"
            "def _level3(u):\n"
            "    return requests.get(u)\n"
            "\n"
            "\n"
            "def _level2(u):\n"
            "    return _level3(u)\n"
            "\n"
            "\n"
            "def _level1(u):\n"
            "    return _level2(u)\n"
            "\n"
            "\n"
            "def main():\n"
            "    return _level1('https://x')\n"
        )
        reached = reachable_external_symbols(build_call_graph(project))
        assert "requests.get" in reached

    def test_import_alias_is_resolved(self, tmp_path):
        project = tmp_path / "aliased"
        project.mkdir()
        (project / "m.py").write_text(
            "import numpy as np\n"
            "\n"
            "\n"
            "def main():\n"
            "    return np.load('f.npy')\n"
        )
        assert "numpy.load" in build_call_graph(project).external_calls

    def test_from_import_is_resolved(self, tmp_path):
        project = tmp_path / "fromimp"
        project.mkdir()
        (project / "m.py").write_text(
            "from yaml import load\n"
            "\n"
            "\n"
            "def main():\n"
            "    return load('a: 1')\n"
        )
        assert "yaml.load" in build_call_graph(project).external_calls

    def test_syntax_error_is_recorded_not_raised(self, tmp_path):
        project = tmp_path / "broken"
        project.mkdir()
        (project / "bad.py").write_text("def (:\n")
        (project / "good.py").write_text("def main():\n    return 1\n")

        graph = build_call_graph(project)
        assert len(graph.parse_errors) == 1
        assert "good.main" in graph.nodes

    def test_test_directories_are_excluded(self, tmp_path):
        project = tmp_path / "withtests"
        (project / "tests").mkdir(parents=True)
        (project / "main.py").write_text("def main():\n    return 1\n")
        (project / "tests" / "test_x.py").write_text(
            "import yaml\n"
            "\n"
            "\n"
            "def test_a():\n"
            "    return yaml.load('a: 1')\n"
        )
        # Test-only usage must not make a symbol production-reachable.
        assert "yaml.load" not in build_call_graph(project).external_calls


class TestImportAliases:
    def test_distribution_to_module_mapping(self):
        assert "yaml" in import_names_for("pyyaml")
        assert "sklearn" in import_names_for("scikit-learn")
        assert "pil" in import_names_for("pillow")

    def test_plain_name_maps_to_itself(self):
        assert "requests" in import_names_for("requests")
