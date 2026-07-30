"""Bridge between a ScanResult and the Rust/WASM 3D renderer.

Turns a scan into the graph the visualiser draws:

  * one node per SBOM package, plus a synthetic root for the application
  * edges from root to direct dependencies, and parent -> child for transitives
  * an edge is "hot" when it lies on a path to a package with a reachable finding

The whole page is emitted self-contained -- the wasm binary is base64-inlined --
so it works from `file://`, inside a Streamlit iframe, and offline. No asset
server, no CORS, nothing to deploy.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from .callgraph import render_path_detail
from .models import Reachability, ScanResult

VIZ_DIR = Path(__file__).resolve().parents[2] / "viz"
WASM_PATH = VIZ_DIR / "target" / "wasm32-unknown-unknown" / "release" / "depsentry_viz.wasm"
SHELL_PATH = VIZ_DIR / "shell.html"

# Node kinds -- must match the KIND_* constants in viz/src/lib.rs.
KIND_ROOT = 0
KIND_CLEAN = 1
KIND_UNREACHABLE = 2
KIND_REACHABLE = 3

_LIVE = (Reachability.REACHABLE, Reachability.POTENTIALLY_REACHABLE)


class WasmNotBuilt(FileNotFoundError):
    """Raised when the Rust engine has not been compiled yet."""


def build_graph(result: ScanResult) -> dict:
    """Project a ScanResult into nodes/edges for the renderer."""
    packages = result.sbom.packages

    # Aggregate findings per package.
    risk: dict[str, float] = {}
    counts: dict[str, int] = {}
    live: set[str] = set()
    paths: dict[str, str] = {}
    top_vuln: dict[str, str] = {}
    for f in result.findings:
        name = f.package.name
        counts[name] = counts.get(name, 0) + 1
        if f.risk_score >= risk.get(name, 0.0):
            risk[name] = f.risk_score
            top_vuln[name] = f.vulnerability.vuln_id
        if f.reachability in _LIVE:
            live.add(name)
            # Keep the shortest traced path as the node's evidence blurb.
            if f.path_detail and name not in paths:
                paths[name] = render_path_detail(f.path_detail)

    # Index 0 is the synthetic application root.
    nodes: list[dict] = [{
        "name": result.project,
        "version": "",
        "direct": True,
        "kind": KIND_ROOT,
        "risk": 0.0,
        "vulns": 0,
    }]
    index: dict[str, int] = {}

    for pkg in packages:
        if pkg.name in live:
            kind = KIND_REACHABLE
        elif counts.get(pkg.name):
            kind = KIND_UNREACHABLE
        else:
            kind = KIND_CLEAN

        index[pkg.name] = len(nodes)
        nodes.append({
            "name": pkg.name,
            "version": pkg.version,
            "direct": pkg.direct,
            "kind": kind,
            "risk": round(risk.get(pkg.name, 0.0), 2),
            "vulns": counts.get(pkg.name, 0),
            "vuln_id": top_vuln.get(pkg.name, ""),
            "path": paths.get(pkg.name, ""),
        })

    # Edges as [a, b, hot]. An edge is hot when it feeds a live node, so the
    # whole chain from the application to an exploitable package lights up.
    edges: list[list[int]] = []
    for pkg in packages:
        child = index[pkg.name]
        hot = 1 if pkg.name in live else 0

        if pkg.direct or not pkg.parents:
            edges.append([0, child, hot])
        else:
            parent_name = pkg.parents[-1]
            parent = index.get(parent_name)
            if parent is None:
                edges.append([0, child, hot])
            else:
                edges.append([parent, child, hot])
                # Propagate heat up the chain to the root.
                if hot:
                    walk = parent_name
                    seen: set[str] = set()
                    while walk and walk not in seen:
                        seen.add(walk)
                        node_i = index.get(walk)
                        if node_i is None:
                            break
                        src = next((p for p in packages if p.name == walk), None)
                        up = 0 if not src or src.direct or not src.parents else index.get(src.parents[-1], 0)
                        edges.append([up, node_i, 1])
                        walk = src.parents[-1] if src and src.parents and not src.direct else ""

    # Deduplicate, keeping the hot variant when an edge appears both ways.
    merged: dict[tuple[int, int], int] = {}
    for a, b, hot in edges:
        key = (a, b)
        merged[key] = max(merged.get(key, 0), hot)
    edges = [[a, b, h] for (a, b), h in sorted(merged.items())]

    total = len(result.findings)
    actionable = len(result.actionable_findings)

    return {
        "project": result.project,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "packages": len(packages),
            "findings": total,
            "reachable": actionable,
            "suppressed": total - actionable,
            "noise": round(result.noise_reduction() * 100),
        },
    }


def render_html(result: ScanResult, height: int = 640) -> str:
    """Produce the fully self-contained visualiser page."""
    if not WASM_PATH.exists():
        raise WasmNotBuilt(
            f"Rust engine not built at {WASM_PATH}.\n"
            "Build it with:  ./run.sh build-viz"
        )

    shell = SHELL_PATH.read_text(encoding="utf-8")
    wasm_b64 = base64.b64encode(WASM_PATH.read_bytes()).decode("ascii")
    graph = build_graph(result)

    # Order matters: substitute the wasm blob last so a '__HEIGHT__'-like byte
    # sequence inside the base64 payload can never be rewritten.
    shell = shell.replace("__HEIGHT__", str(int(height)))
    shell = shell.replace("__GRAPH_DATA__", json.dumps(graph, separators=(",", ":")))
    shell = shell.replace("__WASM_B64__", wasm_b64)
    return shell


def write_html(result: ScanResult, out_path: str | Path, height: int = 720) -> Path:
    """Write a standalone .html file that opens straight in a browser."""
    page = (
        "<!doctype html>\n<html><head><meta charset='utf-8'>"
        f"<title>DepSentry 3D — {result.project}</title>"
        "<style>html,body{margin:0;padding:0;background:#05070f}</style>"
        "</head><body>\n"
        + render_html(result, height)
        + "\n</body></html>\n"
    )
    path = Path(out_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(page, encoding="utf-8")
    return path
