"""Shared fixtures. Builds throwaway projects and advisory DBs on tmp_path."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from depsentry.models import Vulnerability  # noqa: E402
from depsentry.vulndb import VulnerabilityDB  # noqa: E402


@pytest.fixture
def safe_project(tmp_path: Path) -> Path:
    """A project that imports pyyaml but only calls the SAFE loader.

    This is the central negative case: a CVSS 9.8 advisory on `yaml.load` must
    NOT fire when the application only ever calls `yaml.safe_load`.
    """
    project = tmp_path / "safeapp"
    project.mkdir()
    (project / "requirements.txt").write_text("pyyaml==5.4.1\nrequests==2.28.0\n")
    (project / "main.py").write_text(
        "import yaml\n"
        "import requests\n"
        "\n"
        "\n"
        "def load_settings(stream):\n"
        "    return yaml.safe_load(stream)\n"
        "\n"
        "\n"
        "def main():\n"
        "    return load_settings('a: 1')\n"
    )
    return project


@pytest.fixture
def unsafe_project(tmp_path: Path) -> Path:
    """Same dependencies, but the vulnerable symbol IS on a live path."""
    project = tmp_path / "unsafeapp"
    project.mkdir()
    (project / "requirements.txt").write_text("pyyaml==5.4.1\nrequests==2.28.0\n")
    (project / "main.py").write_text(
        "import yaml\n"
        "import requests\n"
        "\n"
        "\n"
        "def _parse(stream):\n"
        "    return yaml.load(stream)\n"
        "\n"
        "\n"
        "def fetch(url):\n"
        "    return requests.get(url)\n"
        "\n"
        "\n"
        "def main():\n"
        "    return _parse(fetch('https://example.com').text)\n"
    )
    return project


@pytest.fixture
def dynamic_project(tmp_path: Path) -> Path:
    """Imports pyyaml and uses getattr, so no unreachable claim is defensible."""
    project = tmp_path / "dynamicapp"
    project.mkdir()
    (project / "requirements.txt").write_text("pyyaml==5.4.1\n")
    (project / "main.py").write_text(
        "import yaml\n"
        "\n"
        "\n"
        "def main(name, stream):\n"
        "    loader = getattr(yaml, name)\n"
        "    return loader(stream)\n"
    )
    return project


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Small advisory DB with a traceable and an untraceable advisory."""
    db_path = tmp_path / "test_vulns.sqlite3"
    with VulnerabilityDB(db_path) as db:
        db.add(Vulnerability(
            vuln_id="TEST-0001", package="pyyaml", ecosystem="PyPI",
            introduced="0", fixed="6.0.2", cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            summary="RCE via unsafe loader.",
            affected_symbols=("yaml.load", "yaml.unsafe_load"),
            cwe=("CWE-502",), exploit_known=True, network_exposed=True,
        ))
        db.add(Vulnerability(
            vuln_id="TEST-0002", package="requests", ecosystem="PyPI",
            introduced="0", fixed="2.32.0", cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            summary="Header leak on redirect.",
            affected_symbols=("requests.get",),
            cwe=("CWE-200",), network_exposed=True,
        ))
        db.add(Vulnerability(
            vuln_id="TEST-0003", package="requests", ecosystem="PyPI",
            introduced="0", fixed=None, cvss_score=5.0,
            cvss_vector="", summary="Advisory with no symbol data.",
            affected_symbols=(),
        ))
    return db_path
