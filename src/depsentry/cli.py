"""DepSentry command line interface.

    depsentry scan <path> [--fail-on <score>] [--sign KEY] [--out DIR]
    depsentry sbom <path> [--out FILE]
    depsentry verify-log <path>
    depsentry db-info

`--fail-on` gives the CI story: exit code 1 when an actionable finding exceeds
the threshold, 0 otherwise. Unreachable findings never break a build.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .integrity import AuditLog, verify_sbom
from .pipeline import scan_project
from .report import console_summary, write_reports
from .sbom import generate_sbom, write_sbom
from .vulndb import DEFAULT_DB, VulnerabilityDB

DEFAULT_AUDIT_LOG = Path(__file__).resolve().parents[2] / "reports" / "audit.jsonl"


def _warn(message: str) -> None:
    print(f"  note: {message}", file=sys.stderr)


def _cmd_scan(args: argparse.Namespace) -> int:
    result = scan_project(
        args.path,
        db_path=args.db,
        signing_key=args.sign,
        audit_log_path=args.audit_log,
        live=args.live,
        cache_live=args.cache,
        overlay_heuristic=args.overlay_heuristic,
        # EPSS defaults on with --live (real CVE ids to look up) and off for the
        # local synthetic corpus, whose DEPS- ids have no EPSS score anyway.
        epss=(args.live and not args.no_epss),
        remediation_limit=(0 if args.no_llm else args.remediation_limit),
        warn=_warn,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(console_summary(result))

    source = result.stats.get("advisory_source", {})
    if source.get("live") and not args.json:
        print("  advisory source: OSV.dev (live)")
        print(source.get("coverage_report", ""))
        print()

    if args.out:
        paths = write_reports(result, args.out, vex=not args.no_vex)
        if not args.json:
            for kind, path in paths.items():
                print(f"  wrote {kind:9} {path}")
            print()

    if args.fail_on is not None:
        breaching = [
            f for f in result.actionable_findings if f.risk_score >= args.fail_on
        ]
        if breaching:
            print(
                f"FAIL: {len(breaching)} actionable finding(s) at or above "
                f"risk {args.fail_on}.",
                file=sys.stderr,
            )
            return 1
        print(f"PASS: no actionable finding reaches risk {args.fail_on}.")

    return 0


def _cmd_sbom(args: argparse.Namespace) -> int:
    sbom = generate_sbom(args.path)
    out = args.out or Path(args.path) / "sbom.cdx.json"
    path = write_sbom(sbom, out)
    direct = sum(1 for p in sbom.packages if p.direct)
    print(
        f"SBOM: {len(sbom.packages)} components "
        f"({direct} direct, {len(sbom.packages) - direct} transitive) -> {path}"
    )
    return 0


def _cmd_verify_log(args: argparse.Namespace) -> int:
    ok, message = AuditLog(args.path).verify()
    print(("OK: " if ok else "TAMPERED: ") + message)
    return 0 if ok else 1


def _cmd_db_info(args: argparse.Namespace) -> int:
    with VulnerabilityDB(args.db) as db:
        advisories = db.all_advisories()

    print(f"Advisory store : {args.db}")
    print(f"Advisories     : {len(advisories)}")

    by_severity: dict[str, int] = {}
    with_symbols = 0
    for a in advisories:
        by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
        if a.affected_symbols:
            with_symbols += 1

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        if severity in by_severity:
            print(f"  {severity:<9} {by_severity[severity]}")
    print(f"With symbol data: {with_symbols}/{len(advisories)} "
          f"({with_symbols / max(len(advisories), 1):.0%}) -- these are traceable.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depsentry",
        description="Reachability-aware software supply chain risk analyzer.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a project for reachable vulnerabilities.")
    scan.add_argument("path", help="Path to the project root.")
    scan.add_argument("--db", default=str(DEFAULT_DB), help="Advisory database path.")
    scan.add_argument("--out", help="Directory to write reports into.")
    scan.add_argument("--sign", help="Signing key: an Ed25519 PEM path or an HMAC secret.")
    scan.add_argument("--audit-log", default=str(DEFAULT_AUDIT_LOG),
                      help="Append-only audit log path.")
    scan.add_argument("--fail-on", type=float, metavar="RISK",
                      help="Exit 1 if an actionable finding reaches this risk score.")
    scan.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")

    live = scan.add_argument_group("live data (network, all opt-in)")
    live.add_argument("--live", action="store_true",
                      help="Query OSV.dev for real advisories instead of the local corpus. "
                           "Falls back to local if OSV is unreachable.")
    live.add_argument("--cache", action="store_true",
                      help="With --live, cache fetched advisories locally for offline reuse.")
    live.add_argument("--overlay-heuristic", action="store_true",
                      help="Attribute a package's known dangerous API surface to advisories "
                           "with no upstream symbol data. Widens reachability; a guess, not a fact.")
    live.add_argument("--no-epss", action="store_true",
                      help="Skip EPSS exploit-probability lookup (on by default with --live).")

    out = scan.add_argument_group("output")
    out.add_argument("--no-vex", action="store_true",
                     help="Do not write vex.json alongside the other reports.")

    llm = scan.add_argument_group("AI remediation (requires ANTHROPIC_API_KEY)")
    llm.add_argument("--no-llm", action="store_true",
                     help="Never call the Anthropic API.")
    llm.add_argument("--remediation-limit", type=int, default=0, metavar="N",
                     help="Generate fix guidance for the top N reachable findings "
                          "(default 0 = off; 10 is a sensible value).")

    scan.set_defaults(func=_cmd_scan)

    sbom = sub.add_parser("sbom", help="Generate a CycloneDX SBOM.")
    sbom.add_argument("path")
    sbom.add_argument("--out")
    sbom.set_defaults(func=_cmd_sbom)

    verify = sub.add_parser("verify-log", help="Verify the audit log hash chain.")
    verify.add_argument("path", nargs="?", default=str(DEFAULT_AUDIT_LOG))
    verify.set_defaults(func=_cmd_verify_log)

    info = sub.add_parser("db-info", help="Summarise the advisory database.")
    info.add_argument("--db", default=str(DEFAULT_DB))
    info.set_defaults(func=_cmd_db_info)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
