"""SBOM generation from a Python project.

Resolution order:
  1. requirements.txt / pyproject.toml pins declared by the project (direct deps)
  2. importlib.metadata for whatever is actually installed (transitive closure)

Declared-but-not-installed packages are still recorded, because a dependency you
cannot resolve is itself a supply chain finding.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from importlib import metadata
from pathlib import Path

from .models import SBOM, Package

# name, optional extras, operator, version -- e.g. "requests[socks]>=2.25.0"
_REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*"
    r"(?:\[(?P<extras>[^\]]*)\])?\s*"
    r"(?P<op>==|>=|<=|~=|!=|>|<)?\s*"
    r"(?P<version>[A-Za-z0-9._*+!-]+)?"
)

_SKIP_PREFIXES = ("#", "-r", "--", "-e", "git+", "http://", "https://")


def _normalise(name: str) -> str:
    """PEP 503 normalisation, so Flask/flask/FLASK collapse to one key."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: Path) -> dict[str, tuple[str | None, str]]:
    """Read a requirements.txt into {normalised_name: (operator, version)}.

    The operator is retained because `==` is authoritative: an exactly pinned
    dependency is the version that will be deployed, whatever happens to be
    installed in the developer's local environment.
    """
    pins: dict[str, tuple[str | None, str]] = {}
    if not path.exists():
        return pins

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(_SKIP_PREFIXES):
            continue
        # Environment markers ("; python_version < '3.11'") don't affect identity.
        line = line.split(";", 1)[0].strip()
        m = _REQ_LINE.match(line)
        if not m or not m.group("name"):
            continue
        pins[_normalise(m.group("name"))] = (m.group("op"), m.group("version") or "*")
    return pins


def parse_pyproject(path: Path) -> dict[str, tuple[str | None, str]]:
    """Read PEP 621 `project.dependencies` from pyproject.toml."""
    pins: dict[str, tuple[str | None, str]] = {}
    if not path.exists():
        return pins

    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return pins

    for dep in doc.get("project", {}).get("dependencies", []) or []:
        m = _REQ_LINE.match(str(dep).split(";", 1)[0].strip())
        if m and m.group("name"):
            pins[_normalise(m.group("name"))] = (m.group("op"), m.group("version") or "*")
    return pins


def _installed_index() -> dict[str, metadata.Distribution]:
    index: dict[str, metadata.Distribution] = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if name:
            index[_normalise(name)] = dist
    return index


def _requires_of(dist: metadata.Distribution) -> list[str]:
    """Runtime dependency names of a distribution, excluding extras-only deps."""
    out: list[str] = []
    for req in dist.requires or []:
        # Skip deps guarded by an extra; they aren't installed by default.
        if "extra ==" in req:
            continue
        m = _REQ_LINE.match(req.split(";", 1)[0].strip())
        if m and m.group("name"):
            out.append(_normalise(m.group("name")))
    return out


def _license_of(dist: metadata.Distribution | None) -> str | None:
    """Read the License field without tripping the implicit-None deprecation."""
    if dist is None:
        return None
    return dist.metadata.get("License") or None


def _fingerprint(dist: metadata.Distribution) -> str | None:
    """Hash of the distribution's RECORD, used as a tamper-evidence anchor.

    A real deployment would compare wheel digests against the index; RECORD is
    the closest stable equivalent available purely offline.
    """
    try:
        record = dist.read_text("RECORD")
    except (FileNotFoundError, OSError):
        return None
    if not record:
        return None
    return hashlib.sha256(record.encode()).hexdigest()


def generate_sbom(project_path: str | Path, max_depth: int = 4) -> SBOM:
    """Build an SBOM by walking the installed dependency graph breadth-first.

    Direct dependencies come from the project's declared pins; everything
    reachable from them in the installed metadata graph is marked transitive.
    """
    root = Path(project_path).expanduser().resolve()
    project_name = root.name

    declared = parse_requirements(root / "requirements.txt")
    declared.update(parse_pyproject(root / "pyproject.toml"))

    installed = _installed_index()
    packages: dict[str, Package] = {}

    # Level 0: everything the project declares.
    frontier: list[tuple[str, tuple[str, ...]]] = [(n, ()) for n in declared]

    for name, _ in frontier:
        dist = installed.get(name)
        operator, declared_version = declared[name]

        # An exact pin is what ships, so it beats the local install. Anything
        # looser falls back to the resolved environment, then to the range text.
        if operator == "==" and declared_version != "*":
            version = declared_version
        elif dist is not None:
            version = dist.version
        else:
            version = declared_version

        packages[name] = Package(
            name=name,
            version=version,
            direct=True,
            parents=(),
            license=_license_of(dist),
            sha256=_fingerprint(dist) if dist else None,
        )

    # Levels 1..max_depth: transitive closure over installed metadata.
    depth = 0
    while frontier and depth < max_depth:
        next_frontier: list[tuple[str, tuple[str, ...]]] = []
        for name, chain in frontier:
            dist = installed.get(name)
            if dist is None:
                continue
            for child in _requires_of(dist):
                if child in packages:
                    continue
                child_dist = installed.get(child)
                if child_dist is None:
                    continue
                parents = (*chain, name)
                packages[child] = Package(
                    name=child,
                    version=child_dist.version,
                    direct=False,
                    parents=parents,
                    license=_license_of(child_dist),
                    sha256=_fingerprint(child_dist),
                )
                next_frontier.append((child, parents))
        frontier = next_frontier
        depth += 1

    ordered = sorted(packages.values(), key=lambda p: (not p.direct, p.name))
    return SBOM(project=project_name, packages=ordered)


def write_sbom(sbom: SBOM, out_path: str | Path) -> Path:
    """Write the CycloneDX document to disk and return the path."""
    import json

    path = Path(out_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sbom.to_cyclonedx(), indent=2), encoding="utf-8")
    return path
