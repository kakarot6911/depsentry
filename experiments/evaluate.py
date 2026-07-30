"""Research evaluation: does reachability-aware prioritisation beat a CVSS gate?

Hypothesis
    H1  Reachability filtering cuts the volume of findings a developer must
        review, without dropping genuinely exploitable ones (recall holds).
    H2  Reachability-aware ranking places truly exploitable findings higher
        than a CVSS-only ordering does.

Conditions
    baseline_cvss7   flag every finding with CVSS >= 7.0   (the common CI gate)
    baseline_all     flag every finding                    (no triage at all)
    depsentry        flag findings judged actionable       (reachable + risk >= 4)

Evaluation universe
    Only (project, advisory) pairs the SBOM matcher actually surfaces are
    scored. Advisory matching is not the variable under test -- reachability is
    -- so pairs that never reach the reachability stage are excluded from both
    conditions equally.

Outputs reports/evaluation.json and reports/evaluation.md.
"""

from __future__ import annotations

import json
import statistics
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from depsentry.models import Reachability  # noqa: E402
from depsentry.pipeline import scan_project  # noqa: E402
from depsentry.risk import rank_by_baseline  # noqa: E402

BENCHMARK_DIR = ROOT / "benchmark"
REPORTS_DIR = ROOT / "reports"


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif not predicted and actual:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def alert_volume(self) -> int:
        """How many findings a developer is asked to look at."""
        return self.tp + self.fp

    def summary(self) -> dict:
        return {
            **asdict(self),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "alert_volume": self.alert_volume,
        }


def average_precision(ranked_labels: list[bool]) -> float:
    """Average precision of one ranked list (1.0 = all positives on top)."""
    hits = 0
    total = 0.0
    for i, is_positive in enumerate(ranked_labels, start=1):
        if is_positive:
            hits += 1
            total += hits / i
    positives = sum(ranked_labels)
    return total / positives if positives else 0.0


def run_evaluation(benchmark_dir: Path = BENCHMARK_DIR) -> dict:
    manifest_path = benchmark_dir / "ground_truth.json"
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"{manifest_path} missing. Run `python3 data/make_benchmark.py` first."
        )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    projects = manifest["projects"]

    cm_depsentry = ConfusionMatrix()
    cm_cvss7 = ConfusionMatrix()
    cm_all = ConfusionMatrix()

    # Ablation: which single signal carries the result?
    cm_reach_only = ConfusionMatrix()   # reachability, ignore risk threshold

    ap_depsentry: list[float] = []
    ap_baseline: list[float] = []
    per_project: list[dict] = []
    reachability_counts: dict[str, int] = {}
    skipped = 0

    for name in sorted(projects):
        project_dir = benchmark_dir / name
        if not project_dir.is_dir():
            continue

        truth: dict[str, bool] = projects[name]["exploitable"]
        result = scan_project(project_dir)

        scored = [f for f in result.findings if f.vulnerability.vuln_id in truth]
        skipped += len(result.findings) - len(scored)
        if not scored:
            continue

        for f in scored:
            actual = truth[f.vulnerability.vuln_id]
            cm_depsentry.add(f.actionable, actual)
            cm_cvss7.add(f.vulnerability.cvss_score >= 7.0, actual)
            cm_all.add(True, actual)
            cm_reach_only.add(
                f.reachability
                in (Reachability.REACHABLE, Reachability.POTENTIALLY_REACHABLE),
                actual,
            )
            key = f.reachability.value
            reachability_counts[key] = reachability_counts.get(key, 0) + 1

        # Ranking quality: DepSentry order vs CVSS-only order.
        ds_labels = [truth[f.vulnerability.vuln_id] for f in scored]
        bl_labels = [
            truth[f.vulnerability.vuln_id] for f in rank_by_baseline(scored)
        ]
        ap_depsentry.append(average_precision(ds_labels))
        ap_baseline.append(average_precision(bl_labels))

        per_project.append({
            "project": name,
            "kind": projects[name]["kind"],
            "packages": len(result.sbom.packages),
            "findings": len(scored),
            "truly_exploitable": sum(ds_labels),
            "depsentry_flagged": sum(1 for f in scored if f.actionable),
            "cvss7_flagged": sum(1 for f in scored if f.vulnerability.cvss_score >= 7.0),
            "noise_reduction": round(1 - (sum(1 for f in scored if f.actionable)
                                          / max(len(scored), 1)), 4),
        })

    total_findings = cm_all.total
    volume_reduction = (
        1 - (cm_depsentry.alert_volume / cm_cvss7.alert_volume)
        if cm_cvss7.alert_volume else 0.0
    )

    report = {
        "corpus": {
            "projects_evaluated": len(per_project),
            "advisory_instances_scored": total_findings,
            "truly_exploitable": cm_all.tp,
            "prevalence": round(cm_all.tp / total_findings, 4) if total_findings else 0.0,
            "unscored_pairs_excluded": skipped,
            "seed": manifest["seed"],
            "reach_rate_configured": manifest["reach_rate"],
        },
        "reachability_distribution": reachability_counts,
        "conditions": {
            "depsentry": cm_depsentry.summary(),
            "baseline_cvss7": cm_cvss7.summary(),
            "baseline_all": cm_all.summary(),
        },
        "ablation": {
            "reachability_filter_only": cm_reach_only.summary(),
            "note": "Isolates the reachability signal from the risk-score threshold.",
        },
        "ranking": {
            "map_depsentry": round(statistics.fmean(ap_depsentry), 4) if ap_depsentry else 0.0,
            "map_baseline_cvss": round(statistics.fmean(ap_baseline), 4) if ap_baseline else 0.0,
        },
        "headline": {
            "alert_volume_depsentry": cm_depsentry.alert_volume,
            "alert_volume_cvss7": cm_cvss7.alert_volume,
            "alert_volume_no_triage": cm_all.alert_volume,
            "volume_reduction_vs_cvss7": round(volume_reduction, 4),
            "recall_retained": round(cm_depsentry.recall, 4),
            "precision_gain_vs_cvss7": round(
                cm_depsentry.precision - cm_cvss7.precision, 4
            ),
        },
        "per_project": per_project,
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "evaluation.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    _write_markdown(report, REPORTS_DIR / "evaluation.md")
    return report


def _write_markdown(report: dict, path: Path) -> None:
    c = report["corpus"]
    cond = report["conditions"]
    head = report["headline"]

    def row(label: str, m: dict) -> str:
        return (
            f"| {label} | {m['alert_volume']} | {m['precision']:.3f} | "
            f"{m['recall']:.3f} | {m['f1']:.3f} | {m['tp']} | {m['fp']} | {m['fn']} |"
        )

    lines = [
        "# DepSentry Evaluation Results",
        "",
        "Generated by `experiments/evaluate.py`. Reproduce with:",
        "",
        "```bash",
        "python3 data/seed_vulndb.py",
        "python3 data/make_benchmark.py",
        "python3 experiments/evaluate.py",
        "```",
        "",
        "## Corpus",
        "",
        f"- Projects evaluated: **{c['projects_evaluated']}**",
        f"- Advisory instances scored: **{c['advisory_instances_scored']}**",
        f"- Truly exploitable (ground truth): **{c['truly_exploitable']}** "
        f"({c['prevalence']:.1%} prevalence)",
        f"- Random seed: `{c['seed']}` (corpus is deterministic)",
        f"- Pairs excluded as unscored: {c['unscored_pairs_excluded']}",
        "",
        "## Detection performance",
        "",
        "| Condition | Alerts shown | Precision | Recall | F1 | TP | FP | FN |",
        "|---|---|---|---|---|---|---|---|",
        row("DepSentry (reachability-aware)", cond["depsentry"]),
        row("Baseline: CVSS >= 7.0 gate", cond["baseline_cvss7"]),
        row("Baseline: no triage", cond["baseline_all"]),
        "",
        "## Headline result",
        "",
        f"- Alert volume: **{head['alert_volume_cvss7']} -> "
        f"{head['alert_volume_depsentry']}** "
        f"(**{head['volume_reduction_vs_cvss7']:.1%}** reduction vs the CVSS gate)",
        f"- Recall retained: **{head['recall_retained']:.1%}**",
        f"- Precision gain over CVSS gate: **{head['precision_gain_vs_cvss7']:+.3f}**",
        "",
        "## Ranking quality (Mean Average Precision)",
        "",
        f"- DepSentry ordering: **{report['ranking']['map_depsentry']:.3f}**",
        f"- CVSS-only ordering: **{report['ranking']['map_baseline_cvss']:.3f}**",
        "",
        "## Ablation",
        "",
        "| Variant | Precision | Recall | F1 |",
        "|---|---|---|---|",
        f"| Full DepSentry | {cond['depsentry']['precision']:.3f} | "
        f"{cond['depsentry']['recall']:.3f} | {cond['depsentry']['f1']:.3f} |",
        f"| Reachability filter only | "
        f"{report['ablation']['reachability_filter_only']['precision']:.3f} | "
        f"{report['ablation']['reachability_filter_only']['recall']:.3f} | "
        f"{report['ablation']['reachability_filter_only']['f1']:.3f} |",
        "",
        "## Reachability distribution",
        "",
        "| Verdict | Count |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in sorted(report["reachability_distribution"].items())],
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    r = run_evaluation()
    h = r["headline"]
    print("\n=== DepSentry evaluation ===")
    print(f"projects            : {r['corpus']['projects_evaluated']}")
    print(f"advisory instances  : {r['corpus']['advisory_instances_scored']}")
    print(f"truly exploitable   : {r['corpus']['truly_exploitable']}")
    print()
    for name, m in r["conditions"].items():
        print(f"{name:16} alerts={m['alert_volume']:4}  P={m['precision']:.3f} "
              f"R={m['recall']:.3f}  F1={m['f1']:.3f}")
    print()
    print(f"volume reduction vs CVSS>=7 gate : {h['volume_reduction_vs_cvss7']:.1%}")
    print(f"recall retained                  : {h['recall_retained']:.1%}")
    print(f"MAP  depsentry={r['ranking']['map_depsentry']:.3f}  "
          f"cvss={r['ranking']['map_baseline_cvss']:.3f}")
    print(f"\nWrote reports/evaluation.json and reports/evaluation.md")
