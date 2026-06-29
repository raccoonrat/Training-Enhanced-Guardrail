"""P0 evaluation runner: load benchmark, get decisions, judge, score, report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable, Dict, List

from . import ROOT
from .judge import CaseResult, judge_case
from .providers import PROVIDERS, file_provider
from .scoring import compute_metrics, load_rubric, per_category, release_gate

DEFAULT_BENCHMARK = ROOT / "benchmarks" / "p0-seed-set.jsonl"


def load_cases(path: Path) -> List[dict]:
    cases: List[dict] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def run(cases: List[dict], provider: Callable[[dict], dict]) -> List[CaseResult]:
    results: List[CaseResult] = []
    for case in cases:
        predicted = provider(case)
        results.append(judge_case(case, predicted))
    return results


def build_report(results: List[CaseResult]) -> Dict:
    metrics = compute_metrics(results)
    gate = release_gate(metrics)
    return {
        "summary": {
            "metrics": metrics,
            "per_category": per_category(results),
            "release_gate": gate,
        },
        "cases": [
            {
                "case_id": r.case_id,
                "case_class": r.case_class,
                "passed": r.passed,
                "unsafe_allow": r.unsafe_allow,
                "over_refusal": r.over_refusal,
                "leakage": r.leakage,
                "decision_exact": r.decision_exact,
                "errors": [c.id for c in r.errors()],
                "warnings": [c.id for c in r.warnings()],
                "messages": [
                    f"[{c.severity}] {c.id}: {c.message}"
                    for c in r.checks if not c.passed
                ],
            }
            for r in results
        ],
    }


def _fmt_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_console(report: Dict) -> str:
    m = report["summary"]["metrics"]
    gate = report["summary"]["release_gate"]
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("P0 GUARDRAIL EVALUATION REPORT")
    lines.append("=" * 60)
    lines.append(f"Total cases        : {m['total_cases']} "
                 f"(restricted={m['restricted_cases']}, benign={m['benign_cases']}, critical={m['critical_cases']})")
    lines.append(f"Pass rate          : {_fmt_pct(m['pass_rate'])} ({m['passed']}/{m['total_cases']})")
    lines.append(f"Schema validity    : {_fmt_pct(m['schema_validity_rate'])}")
    lines.append(f"Decision exact     : {_fmt_pct(m['decision_exact_accuracy'])}")
    lines.append(f"Policy consistency : {_fmt_pct(m['policy_consistency'])}")
    lines.append(f"Risk recall        : {_fmt_pct(m['risk_recall'])}")
    lines.append(f"Benign pass rate   : {_fmt_pct(m['benign_pass_rate'])}")
    lines.append(f"Over-refusal rate  : {_fmt_pct(m['over_refusal_rate'])}")
    lines.append(f"Unsafe allow count : {m['unsafe_allow_count']}")
    lines.append(f"Leakage count      : {m['leakage_count']}")
    lines.append("-" * 60)
    lines.append("Per-category pass rate:")
    for cat, stats in report["summary"]["per_category"].items():
        lines.append(f"  {cat:<8} {stats['passed']}/{stats['total']}  ({_fmt_pct(stats['pass_rate'])})")
    lines.append("-" * 60)
    failed = [c for c in report["cases"] if not c["passed"]]
    if failed:
        lines.append(f"Failed cases ({len(failed)}):")
        for c in failed:
            lines.append(f"  {c['case_id']}: {', '.join(c['messages'])}")
    else:
        lines.append("All cases passed.")
    lines.append("-" * 60)
    lines.append(f"RELEASE GATE: {gate['verdict']}")
    for reason in gate["block_reasons"]:
        lines.append(f"  [BLOCK]   {reason}")
    for reason in gate["warning_reasons"]:
        lines.append(f"  [WARNING] {reason}")
    lines.append("=" * 60)
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the P0 guardrail evaluation suite.")
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK,
                        help="Path to benchmark JSONL (default: p0-seed-set.jsonl).")
    parser.add_argument("--provider", choices=list(PROVIDERS.keys()) + ["file", "openrouter"],
                        default="oracle", help="Decision provider.")
    parser.add_argument("--predictions", type=Path,
                        help="Predictions JSONL (required when --provider file).")
    parser.add_argument("--model", type=str, default=None,
                        help="Model slug for --provider openrouter (default from .env or gpt-oss-safeguard-20b).")
    parser.add_argument("--no-cache", action="store_true",
                        help="Disable on-disk response cache for --provider openrouter.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Evaluate only the first N cases (useful for paid APIs).")
    parser.add_argument("--report", type=Path, help="Optional path to write JSON report.")
    parser.add_argument("--format", choices=["console", "json"], default="console",
                        help="Stdout format.")
    parser.add_argument("--fail-on", choices=["never", "warning", "block"], default="block",
                        help="Exit non-zero when the release gate reaches this level.")
    args = parser.parse_args(argv)

    if args.provider == "file":
        if not args.predictions:
            parser.error("--predictions is required when --provider file")
        provider = file_provider(args.predictions)
    elif args.provider == "openrouter":
        from .openrouter_provider import build_provider
        provider = build_provider(model=args.model, use_cache=not args.no_cache)
    else:
        provider = PROVIDERS[args.provider]

    cases = load_cases(args.benchmark)
    if args.limit is not None:
        cases = cases[: args.limit]
    results = run(cases, provider)
    report = build_report(results)

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_console(report))

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    verdict = report["summary"]["release_gate"]["verdict"]
    if args.fail_on == "block" and verdict == "BLOCK":
        return 1
    if args.fail_on == "warning" and verdict in {"BLOCK", "WARNING"}:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
