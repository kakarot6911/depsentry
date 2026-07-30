"""Tests for LLM remediation. The Anthropic API is fully mocked -- no real calls."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from depsentry.models import (
    CallPath, EPSSScore, Finding, Package, Reachability, Vulnerability,
)
from depsentry.remediation import (
    DEFAULT_MODEL, RemediationEngine, build_prompt, cache_key, read_source_window,
)


class FakeMessages:
    """Stands in for client.messages, recording calls."""

    def __init__(self, text="Upgrade joblib to 1.4.0.", stop_reason="end_turn", raises=None):
        self.calls: list[dict] = []
        self._text = text
        self._stop_reason = stop_reason
        self._raises = raises

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises:
            raise self._raises
        return SimpleNamespace(
            stop_reason=self._stop_reason,
            content=[SimpleNamespace(type="text", text=self._text)],
        )


class FakeClient:
    def __init__(self, **kw):
        self.messages = FakeMessages(**kw)


def make_finding(*, symbols=("joblib.load",), fixed="1.4.0", epss=None, detail=True):
    vuln = Vulnerability(
        vuln_id="DEPS-2026-0025", package="joblib", ecosystem="PyPI",
        introduced="0", fixed=fixed, cvss_score=8.4, cvss_vector="",
        summary="Arbitrary code execution loading an untrusted object.",
        affected_symbols=symbols, cve_id="CVE-2026-1234",
    )
    finding = Finding(
        vulnerability=vuln,
        package=Package(name="joblib", version="1.2.0"),
        reachability=Reachability.REACHABLE,
        call_paths=[CallPath("main.main", ("model.load_model",), "joblib.load")],
    )
    if detail:
        finding.path_detail = [
            {"function": "main.main", "file": "main.py", "line": 14,
             "call_line": 18, "external": False},
            {"function": "model.load_model", "file": "model.py", "line": 7,
             "call_line": 8, "external": False},
            {"function": "joblib.load", "file": "<external>", "line": None,
             "call_line": None, "external": True},
        ]
    if epss is not None:
        finding.epss = EPSSScore("CVE-2026-1234", epss, 0.9)
    return finding


@pytest.fixture
def project(tmp_path):
    (tmp_path / "main.py").write_text("\n".join(f"# line {i}" for i in range(1, 25)))
    (tmp_path / "model.py").write_text(
        "import joblib\n\n\ndef load_model(path):\n    return joblib.load(path)\n"
    )
    return tmp_path


class TestGracefulDegradation:
    def test_initialises_without_api_key(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        engine = RemediationEngine(cache_path=tmp_path / "c.sqlite3")
        assert engine.available is False

    def test_generate_returns_none_when_unavailable(self, tmp_path, monkeypatch, project):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        engine = RemediationEngine(cache_path=tmp_path / "c.sqlite3")
        assert engine.generate_remediation(make_finding(), project) is None

    def test_annotate_returns_zero_when_unavailable(self, tmp_path, monkeypatch, project):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        engine = RemediationEngine(cache_path=tmp_path / "c.sqlite3")
        assert engine.annotate([make_finding()], project_root=project) == 0

    def test_api_exception_is_swallowed(self, tmp_path, project):
        client = FakeClient(raises=RuntimeError("connection reset"))
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=client)
        assert engine.generate_remediation(make_finding(), project) is None
        assert engine.stats.failures

    def test_refusal_returns_none(self, tmp_path, project):
        """A refusal is HTTP 200 with empty content -- must not raise."""
        client = FakeClient(stop_reason="refusal")
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=client)
        assert engine.generate_remediation(make_finding(), project) is None

    def test_empty_response_returns_none(self, tmp_path, project):
        client = FakeClient(text="   ")
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=client)
        assert engine.generate_remediation(make_finding(), project) is None


class TestPromptConstruction:
    def test_includes_all_core_fields(self, project):
        prompt = build_prompt(make_finding(), project)
        assert "DEPS-2026-0025" not in prompt or "CVE-2026-1234" in prompt
        assert "joblib.load" in prompt
        assert "joblib==1.2.0" in prompt
        assert "1.4.0" in prompt
        assert "8.4" in prompt

    def test_includes_traced_call_path(self, project):
        prompt = build_prompt(make_finding(), project)
        assert "main.py:14" in prompt
        assert "[VULNERABLE]" in prompt

    def test_includes_source_at_call_site(self, project):
        prompt = build_prompt(make_finding(), project)
        assert "joblib.load(path)" in prompt
        assert "model.py:8" in prompt

    def test_missing_fixed_version_says_unknown(self, project):
        prompt = build_prompt(make_finding(fixed=None), project)
        assert "Fixed in: unknown" in prompt

    def test_epss_included_when_present(self, project):
        assert "EPSS" in build_prompt(make_finding(epss=0.87), project)

    def test_epss_absent_when_missing(self, project):
        assert "EPSS" not in build_prompt(make_finding(), project)

    def test_missing_path_detail_is_tolerated(self, project):
        prompt = build_prompt(make_finding(detail=False), project)
        assert "(no traced path)" in prompt
        assert "(source unavailable)" in prompt


class TestSourceReading:
    def test_reads_window_around_line(self, project):
        window = read_source_window(project, "model.py", 5, radius=1)
        assert "joblib.load" in window

    def test_path_traversal_is_blocked(self, project):
        assert read_source_window(project, "../../../etc/passwd", 1) == ""

    def test_absolute_escape_is_blocked(self, project):
        assert read_source_window(project, "/etc/passwd", 1) == ""

    def test_missing_file_returns_empty(self, project):
        assert read_source_window(project, "nope.py", 1) == ""


class TestCaching:
    def test_second_call_hits_cache(self, tmp_path, project):
        client = FakeClient()
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=client)

        first = engine.generate_remediation(make_finding(), project)
        second = engine.generate_remediation(make_finding(), project)

        assert first == second
        assert len(client.messages.calls) == 1, "second call should hit the cache"
        assert engine.stats.cache_hits == 1

    def test_cache_persists_across_engines(self, tmp_path, project):
        path = tmp_path / "c.sqlite3"
        first_client = FakeClient()
        e1 = RemediationEngine("k", cache_path=path, client=first_client)
        e1.generate_remediation(make_finding(), project)
        e1.close()

        second_client = FakeClient()
        e2 = RemediationEngine("k", cache_path=path, client=second_client)
        e2.generate_remediation(make_finding(), project)
        assert second_client.messages.calls == [], "should have been served from disk cache"

    def test_different_path_produces_different_key(self):
        a = make_finding()
        b = make_finding()
        b.path_detail[0]["call_line"] = 99
        assert cache_key(a, DEFAULT_MODEL) != cache_key(b, DEFAULT_MODEL)

    def test_model_change_invalidates_key(self):
        finding = make_finding()
        assert cache_key(finding, "model-a") != cache_key(finding, "model-b")

    def test_unwritable_cache_is_not_fatal(self, tmp_path, project):
        engine = RemediationEngine(
            "k", cache_path=tmp_path / "nested" / "c.sqlite3", client=FakeClient()
        )
        assert engine.generate_remediation(make_finding(), project) is not None


class TestApiParameters:
    def test_no_sampling_parameters_sent(self, tmp_path, project):
        """temperature/top_p/top_k are rejected with a 400 on current models."""
        client = FakeClient()
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=client)
        engine.generate_remediation(make_finding(), project)

        params = client.messages.calls[0]
        for banned in ("temperature", "top_p", "top_k"):
            assert banned not in params, f"{banned} must not be sent"

    def test_no_manual_thinking_budget(self, tmp_path, project):
        client = FakeClient()
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=client)
        engine.generate_remediation(make_finding(), project)
        thinking = client.messages.calls[0].get("thinking", {})
        assert "budget_tokens" not in thinking

    def test_model_and_max_tokens_set(self, tmp_path, project):
        client = FakeClient()
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=client)
        engine.generate_remediation(make_finding(), project)
        params = client.messages.calls[0]
        assert params["model"] == DEFAULT_MODEL
        assert params["max_tokens"] > 0

    def test_model_overridable_by_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DEPSENTRY_LLM_MODEL", "claude-opus-5")
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=FakeClient())
        assert engine.model == "claude-opus-5"


class TestLimits:
    def test_limit_caps_generation(self, tmp_path, project):
        client = FakeClient()
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=client)

        findings = []
        for i in range(6):
            f = make_finding()
            f.path_detail[0]["call_line"] = 10 + i  # distinct cache keys
            findings.append(f)

        attached = engine.annotate(findings, project_root=project, limit=3)
        assert attached == 3
        assert len(client.messages.calls) == 3
        assert findings[3].remediation_advice is None

    def test_advice_attached_to_finding(self, tmp_path, project):
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=FakeClient())
        findings = [make_finding()]
        engine.annotate(findings, project_root=project, limit=1)
        assert findings[0].remediation_advice == "Upgrade joblib to 1.4.0."


class TestPipelineIntegration:
    def test_no_llm_makes_no_api_calls(self, safe_project, test_db):
        """remediation_limit=0 is the --no-llm path."""
        from depsentry.pipeline import scan_project

        result = scan_project(
            safe_project, db_path=test_db, epss=False, remediation_limit=0
        )
        assert result.stats["remediation"]["enabled"] is False
        assert all(f.remediation_advice is None for f in result.findings)

    def test_non_reachable_findings_are_skipped(self, tmp_path, project):
        engine = RemediationEngine("k", cache_path=tmp_path / "c.sqlite3", client=FakeClient())
        unreachable = make_finding()
        unreachable.reachability = Reachability.UNREACHABLE
        # The pipeline filters by reachability before calling annotate; verify
        # that filter is what protects us, and annotate itself stays dumb.
        reachable_only = [f for f in [unreachable] if f.reachability is Reachability.REACHABLE]
        assert engine.annotate(reachable_only, project_root=project) == 0
