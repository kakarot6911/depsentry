"""DepSentry Streamlit dashboard.

Run:  streamlit run dashboard/app.py

Three views:
  Scan       -- run an analysis and read the ranked findings with evidence
  Benchmark  -- the evaluation results, DepSentry vs the CVSS gate
  Advisories -- browse the local advisory corpus
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from depsentry.callgraph import render_path_detail  # noqa: E402
from depsentry.pipeline import scan_project  # noqa: E402
from depsentry.report import to_markdown  # noqa: E402
from depsentry.vulndb import DEFAULT_DB, VulnerabilityDB  # noqa: E402

st.set_page_config(page_title="DepSentry", page_icon="D", layout="wide")

SEVERITY_COLOR = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#0369a1",
    "NONE": "#64748b",
}


@st.cache_data(show_spinner=False)
def _run_scan(path: str) -> dict:
    return scan_project(path).to_dict()


@st.cache_data(show_spinner=False)
def _load_advisories() -> pd.DataFrame:
    with VulnerabilityDB(DEFAULT_DB) as db:
        rows = [
            {
                "ID": a.vuln_id,
                "Package": a.package,
                "CVSS": a.cvss_score,
                "Severity": a.severity.value,
                "Fixed in": a.fixed or "-",
                "Symbols": ", ".join(a.affected_symbols) or "-",
                "Exploit known": a.exploit_known,
                "Summary": a.summary,
            }
            for a in db.all_advisories()
        ]
    return pd.DataFrame(rows)


def _source_window(project_root: str, rel_file: str, line: int, radius: int = 2) -> str | None:
    """Read a small window of source around a call site.

    Path is resolved and confined to the scanned project, so a crafted
    path_detail entry cannot make the dashboard read arbitrary files.
    """
    try:
        root = Path(project_root).expanduser().resolve()
        target = (root / rel_file).resolve()
        target.relative_to(root)
        if not target.is_file():
            return None
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None

    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    return "\n".join(
        f"{n + 1:>4} {'>' if n + 1 == line else ' '} {lines[n]}"
        for n in range(start, end)
    )


def _call_path_inspector(detail: list[dict], project_root: str) -> None:
    """Render a traced call path as a chain with source windows.

    This is the "show me the proof" view: every hop names a file and line, and
    the actual source at each call site is displayed inline.
    """
    st.markdown("**Call Path Inspector**")

    for i, hop in enumerate(detail):
        is_last = i == len(detail) - 1
        is_first = i == 0

        if is_first:
            badge, colour = "ENTRYPOINT", "#15803d"
        elif is_last:
            badge, colour = "VULNERABLE", "#b91c1c"
        else:
            badge, colour = f"HOP {i}", "#475569"

        location = (
            f"{hop['file']}:{hop['line']}" if hop.get("line") is not None else "external"
        )
        st.markdown(
            f"<div style='display:flex;align-items:center;gap:10px;margin:2px 0'>"
            f"<span style='background:{colour};color:#fff;padding:1px 8px;"
            f"border-radius:10px;font-size:10px;font-weight:700'>{badge}</span>"
            f"<code>{hop['function']}</code>"
            f"<span style='color:#64748b;font-size:11px'>{location}</span></div>",
            unsafe_allow_html=True,
        )

        if hop.get("call_line") and not hop.get("external"):
            window = _source_window(project_root, hop["file"], hop["call_line"])
            if window:
                st.code(window, language="python")
            st.markdown(
                f"<div style='color:#64748b;font-size:11px;margin-left:14px'>"
                f"↓ calls at line {hop['call_line']}</div>",
                unsafe_allow_html=True,
            )

    st.text_area(
        "Copy path as text",
        render_path_detail(detail),
        height=110,
        key=f"path_{hash(str(detail))}",
    )


def _discover_projects() -> list[str]:
    candidates: list[str] = []
    bench = ROOT / "benchmark"
    if bench.is_dir():
        candidates += [str(p) for p in sorted(bench.iterdir()) if p.is_dir()]
    return candidates


# --------------------------------------------------------------------------

st.title("DepSentry")
st.caption(
    "Reachability-aware software supply chain risk analysis - "
    "Semester VII Integrated Project, SSPU Pune"
)

tab_3d, tab_scan, tab_bench, tab_adv = st.tabs(
    ["3D attack surface", "Scan", "Benchmark results", "Advisory corpus"]
)


with tab_3d:
    st.caption(
        "Force-directed dependency graph. Layout, camera and projection run in "
        "Rust compiled to WebAssembly; the browser only rasterises. "
        "Drag to rotate, scroll to zoom, hover a node for detail."
    )

    default_target = str(ROOT / "examples" / "showcase_app")
    options = [default_target] + _discover_projects() + [str(ROOT)]

    c1, c2 = st.columns([4, 1])
    with c1:
        viz_path = st.selectbox("Project", options, index=0, key="viz_pick")
    with c2:
        st.write("")
        st.write("")
        viz_height = st.selectbox("Height", [560, 700, 860], index=1, key="viz_h")

    try:
        from depsentry.viz3d import WasmNotBuilt, render_html

        with st.spinner("Scanning and building the scene..."):
            html = render_html(scan_project(viz_path), height=viz_height)
        components.html(html, height=viz_height + 12, scrolling=False)

        st.caption(
            "Red = a vulnerable symbol reachable from an entrypoint. "
            "Amber = vulnerable but never called, suppressed. "
            "Blue = clean. Node size scales with fused risk."
        )
    except WasmNotBuilt as exc:
        st.error(str(exc))
        st.code("./run.sh build-viz", language="bash")
    except Exception as exc:  # noqa: BLE001 - surface any render failure in-page
        st.error(f"Could not render the 3D view: {exc}")


with tab_scan:
    projects = _discover_projects()
    col_a, col_b = st.columns([3, 1])
    with col_a:
        if projects:
            choice = st.selectbox("Benchmark project", ["(custom path)"] + projects)
            path = st.text_input("Project path", value=(
                "" if choice == "(custom path)" else choice
            ))
        else:
            path = st.text_input("Project path", value=str(ROOT))
    with col_b:
        st.write("")
        st.write("")
        run = st.button("Scan", type="primary", use_container_width=True)

    if run and path:
        if not Path(path).is_dir():
            st.error(f"Not a directory: {path}")
        else:
            with st.spinner("Building SBOM, call graph and reachability set..."):
                data = _run_scan(path)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Packages", data["package_count"])
            m2.metric("Total findings", data["total_findings"])
            m3.metric("Actionable", data["actionable_findings"])
            m4.metric("Noise reduction", f"{data['noise_reduction']:.0%}")

            breakdown = data["stats"].get("reachability_breakdown", {})
            if breakdown:
                st.bar_chart(pd.Series(breakdown, name="findings"))

            findings = data["findings"]
            if not findings:
                st.success("No advisories matched this project's dependencies.")
            else:
                df = pd.DataFrame([{
                    "Rank": f["rank"],
                    "ID": f["vuln_id"],
                    "Package": f"{f['package']} {f['version']}",
                    "CVSS": f["cvss"],
                    "Risk": f["risk_score"],
                    "Reachability": f["reachability"],
                    "Actionable": f["actionable"],
                    "Fix": f["fixed_in"] or "-",
                } for f in findings])

                st.subheader("Findings")
                st.dataframe(df, use_container_width=True, hide_index=True)

                st.subheader("Evidence")
                actionable = [f for f in findings if f["actionable"]]
                if not actionable:
                    st.info(
                        "Every match was suppressed: no vulnerable symbol is "
                        "reachable from an entrypoint."
                    )
                for f in actionable:
                    colour = SEVERITY_COLOR.get(f["severity"], "#64748b")
                    with st.expander(
                        f"#{f['rank']}  {f['vuln_id']}  -  {f['package']} "
                        f"(risk {f['risk_score']}, CVSS {f['cvss']})"
                    ):
                        st.markdown(
                            f"<span style='color:{colour};font-weight:600'>"
                            f"{f['severity']}</span> &nbsp; {f['summary']}",
                            unsafe_allow_html=True,
                        )
                        if f["call_paths"]:
                            st.markdown("**Call paths**")
                            st.code("\n".join(f["call_paths"]), language="text")

                        if f.get("path_detail"):
                            _call_path_inspector(f["path_detail"], path)

                        if f.get("epss"):
                            e = f["epss"]
                            st.markdown(
                                f"**EPSS** — {e['probability']:.2%} chance of "
                                f"exploitation in 30 days · **{e['band']}** · "
                                f"{e['percentile']:.1%} percentile"
                            )

                        if f.get("remediation_advice"):
                            st.markdown("**Suggested fix**")
                            st.info(f["remediation_advice"])

                        st.markdown("**Rationale**")
                        for line in f["rationale"]:
                            st.markdown(f"- {line}")

                with st.expander("Suppressed findings (audit trail)"):
                    supp = [f for f in findings if not f["actionable"]]
                    if supp:
                        st.dataframe(
                            pd.DataFrame([{
                                "ID": f["vuln_id"],
                                "Package": f["package"],
                                "CVSS": f["cvss"],
                                "Verdict": f["reachability"],
                                "Reason": (f["rationale"] or [""])[0],
                            } for f in supp]),
                            use_container_width=True, hide_index=True,
                        )
                    else:
                        st.write("Nothing suppressed.")

                dl1, dl2 = st.columns(2)
                with dl1:
                    st.download_button(
                        "Download Markdown report",
                        to_markdown(scan_project(path)),
                        file_name=f"{data['project']}_report.md",
                        use_container_width=True,
                    )
                with dl2:
                    from depsentry.vex import render_vex, vex_summary

                    scan = scan_project(path)
                    counts = vex_summary(scan)
                    st.download_button(
                        f"Export VEX  ({counts['not_affected']} not-affected)",
                        render_vex(scan),
                        file_name="vex.json",
                        mime="application/json",
                        use_container_width=True,
                        help="OpenVEX 0.2.0 -- machine-readable "
                             "'not affected, and here is why' for your security team.",
                    )


with tab_bench:
    eval_path = ROOT / "reports" / "evaluation.json"
    if not eval_path.exists():
        st.warning("Run `python3 experiments/evaluate.py` to populate this tab.")
    else:
        report = json.loads(eval_path.read_text(encoding="utf-8"))
        corpus, head = report["corpus"], report["headline"]

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Projects", corpus["projects_evaluated"])
        c2.metric("Advisory instances", corpus["advisory_instances_scored"])
        c3.metric("Alert volume cut", f"{head['volume_reduction_vs_cvss7']:.0%}")
        c4.metric("Recall retained", f"{head['recall_retained']:.0%}")

        st.subheader("DepSentry vs baselines")
        st.dataframe(
            pd.DataFrame([{
                "Condition": name,
                "Alerts shown": m["alert_volume"],
                "Precision": round(m["precision"], 3),
                "Recall": round(m["recall"], 3),
                "F1": round(m["f1"], 3),
                "TP": m["tp"], "FP": m["fp"], "FN": m["fn"],
            } for name, m in report["conditions"].items()]),
            use_container_width=True, hide_index=True,
        )

        st.subheader("Ranking quality (MAP)")
        st.bar_chart(pd.Series({
            "DepSentry": report["ranking"]["map_depsentry"],
            "CVSS only": report["ranking"]["map_baseline_cvss"],
        }))

        st.subheader("Per-project noise reduction")
        st.dataframe(pd.DataFrame(report["per_project"]),
                     use_container_width=True, hide_index=True)


with tab_adv:
    df = _load_advisories()
    st.caption(
        "Synthetic corpus (DEPS- identifiers) modelled on OSV advisory "
        "structure. Not claims about real defects in these packages."
    )
    severities = st.multiselect(
        "Severity", sorted(df["Severity"].unique()), default=list(df["Severity"].unique())
    )
    st.dataframe(
        df[df["Severity"].isin(severities)], use_container_width=True, hide_index=True
    )
