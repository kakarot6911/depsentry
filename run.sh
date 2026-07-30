#!/usr/bin/env bash
# DepSentry driver script.
#   ./run.sh setup | test | demo | evaluate | scan <path> | scan-live <path> | viz [path]
#            | build-viz | dashboard | api | all
set -euo pipefail

cd "$(dirname "$0")"
export PYTHONPATH="src"

RULE="=============================================================="

banner() { printf '\n%s\n  %s\n%s\n' "$RULE" "$1" "$RULE"; }

cmd_setup() {
    banner "Setup: advisory database + benchmark corpus"
    python3 data/seed_vulndb.py
    python3 data/make_benchmark.py
}

cmd_test() {
    banner "Test suite"
    python3 -m pytest tests/ -q

    # The Rust engine has its own headless check; skip cleanly if either the
    # wasm build or node is absent, since neither is required for the core tool.
    local wasm="viz/target/wasm32-unknown-unknown/release/depsentry_viz.wasm"
    if [ -f "$wasm" ] && command -v node >/dev/null 2>&1; then
        echo
        echo "-- wasm engine --"
        node viz/smoke.mjs "$wasm"
    else
        echo
        echo "-- wasm engine: skipped (build with ./run.sh build-viz) --"
    fi
}

cmd_demo() {
    banner "Demo: the motivating example"

    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    # Two projects, identical dependencies. Only the called symbol differs.
    for variant in safe unsafe; do
        mkdir -p "$tmp/$variant"
        printf 'pyyaml==5.4.1\nrequests==2.28.0\n' > "$tmp/$variant/requirements.txt"
    done

    cat > "$tmp/safe/main.py" <<'PY'
import yaml
import requests


def load_config(stream):
    return yaml.safe_load(stream)


def main():
    return load_config("a: 1")
PY

    cat > "$tmp/unsafe/main.py" <<'PY'
import yaml
import requests


def load_config(stream):
    return yaml.load(stream)


def main():
    return load_config(requests.get("https://example.com").text)
PY

    echo
    echo ">>> SAFE project  -- calls yaml.safe_load()"
    echo ">>> A conventional scanner fails the build on the CVSS 9.8 PyYAML advisory."
    python3 -m depsentry.cli scan "$tmp/safe"

    echo
    echo ">>> UNSAFE project -- calls yaml.load()"
    echo ">>> Same dependencies, same advisories. Only the called symbol differs."
    python3 -m depsentry.cli scan "$tmp/unsafe"

    echo
    echo "That contrast is the whole thesis: package version is identical,"
    echo "operational risk is not."
    echo
}

cmd_evaluate() {
    banner "Research evaluation"
    if [ ! -f benchmark/ground_truth.json ]; then
        echo "Benchmark missing; running setup first."
        cmd_setup
    fi
    python3 experiments/evaluate.py
}

cmd_scan() {
    if [ $# -lt 1 ]; then
        echo "usage: ./run.sh scan <project-path> [extra depsentry args...]" >&2
        exit 2
    fi
    local target="$1"; shift
    banner "Scanning $target"
    python3 -m depsentry.cli scan "$target" --out reports "$@"
}

cmd_scan_live() {
    if [ $# -lt 1 ]; then
        echo "usage: ./run.sh scan-live <project-path> [extra args...]" >&2
        exit 2
    fi
    local target="$1"; shift
    banner "Live scan (OSV.dev + EPSS): $target"
    echo "  Network required. Falls back to the local corpus if OSV is unreachable."
    echo
    python3 -m depsentry.cli scan "$target" --live --cache --out reports/live "$@"
}

cmd_build_viz() {
    banner "Building Rust 3D engine -> WebAssembly"
    if ! command -v cargo >/dev/null 2>&1; then
        if [ -f "$HOME/.cargo/env" ]; then
            # shellcheck disable=SC1091
            . "$HOME/.cargo/env"
        else
            echo "cargo not found. Install Rust:" >&2
            echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
            echo "  rustup target add wasm32-unknown-unknown" >&2
            exit 2
        fi
    fi
    ( cd viz && cargo build --release --target wasm32-unknown-unknown )
    ls -lh viz/target/wasm32-unknown-unknown/release/depsentry_viz.wasm
}

cmd_viz() {
    local target="${1:-examples/showcase_app}"
    local out="reports/depsentry_3d.html"

    if [ ! -f viz/target/wasm32-unknown-unknown/release/depsentry_viz.wasm ]; then
        echo "wasm engine missing; building it first."
        cmd_build_viz
    fi

    banner "3D attack-surface view: $target"
    python3 - "$target" "$out" <<'PY'
import sys
sys.path.insert(0, "src")
from depsentry.pipeline import scan_project
from depsentry.viz3d import write_html

target, out = sys.argv[1], sys.argv[2]
result = scan_project(target)
path = write_html(result, out)

total = len(result.findings)
live = len(result.actionable_findings)
print(f"  packages   {len(result.sbom.packages)}")
print(f"  findings   {total}  ({live} reachable, {total - live} suppressed)")
print(f"  noise cut  {result.noise_reduction():.0%}")
print(f"  wrote      {path}")
PY

    if command -v open >/dev/null 2>&1; then
        open "$out"
        echo "  opened in your browser"
    else
        echo "  open $out in a browser"
    fi
    echo
}

cmd_dashboard() {
    # Bind loopback by default. Streamlit's own default is 0.0.0.0, which puts
    # the dashboard on the local network -- fine at home, not on campus wifi.
    # Pass --network to opt into exposure deliberately.
    local address="127.0.0.1"
    if [ "${1:-}" = "--network" ]; then
        address="0.0.0.0"
        banner "Streamlit dashboard -> EXPOSED ON LOCAL NETWORK (port 8501)"
        echo "  Anyone on this network can reach it. Ctrl-C when done."
    else
        banner "Streamlit dashboard -> http://127.0.0.1:8501 (loopback only)"
    fi
    streamlit run dashboard/app.py --server.address "$address"
}

cmd_api() {
    # uvicorn already defaults to 127.0.0.1; stated explicitly so the binding
    # is visible rather than inherited.
    local address="127.0.0.1"
    if [ "${1:-}" = "--network" ]; then
        address="0.0.0.0"
        banner "FastAPI -> EXPOSED ON LOCAL NETWORK (port 8000)"
    else
        banner "FastAPI -> http://127.0.0.1:8000/docs (loopback only)"
    fi
    python3 -m uvicorn api.main:app --reload --host "$address" --port 8000
}

cmd_all() {
    cmd_setup
    cmd_test
    cmd_evaluate
    banner "Done"
    echo "  Results : reports/evaluation.md"
    echo "  Docs    : docs/00_SOP_COMPLIANCE.md"
    echo "  Demo    : ./run.sh demo"
    echo
}

case "${1:-all}" in
    setup)     cmd_setup ;;
    test)      cmd_test ;;
    demo)      cmd_demo ;;
    evaluate)  cmd_evaluate ;;
    scan)      shift; cmd_scan "$@" ;;
    scan-live) shift; cmd_scan_live "$@" ;;
    build-viz) cmd_build_viz ;;
    viz)       shift || true; cmd_viz "$@" ;;
    dashboard) shift || true; cmd_dashboard "$@" ;;
    api)       shift || true; cmd_api "$@" ;;
    all)       cmd_all ;;
    *)
        echo "usage: ./run.sh {setup|test|demo|evaluate|scan <path>|" >&2
        echo "                 scan-live <path>|viz [path]|build-viz|dashboard|api|all}" >&2
        echo "       dashboard and api accept --network to bind 0.0.0.0" >&2
        exit 2
        ;;
esac
