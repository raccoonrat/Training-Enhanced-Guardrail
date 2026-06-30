#!/usr/bin/env python3
"""Plan or generate scaled Phase 1.5 training assets.

The first implementation is intentionally a dry-run count planner. It validates
the machine-readable scale config and emits deterministic target counts before
the full JSONL generator is enabled.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "evaluation" / "phase15-scale-config.json"
DEFAULT_REPORT = ROOT / "evaluation" / "phase15-scale-dry-run-report.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _largest_remainder_counts(total: int, shares: dict[str, float]) -> dict[str, int]:
    raw = {key: total * share for key, share in shares.items()}
    counts = {key: int(value) for key, value in raw.items()}
    remainder = total - sum(counts.values())
    order = sorted(raw, key=lambda key: (raw[key] - counts[key], key), reverse=True)
    for key in order[:remainder]:
        counts[key] += 1
    return dict(sorted(counts.items()))


def _validate_share_block(name: str, shares: dict[str, float]) -> list[str]:
    errors: list[str] = []
    total = sum(shares.values())
    if abs(total - 1.0) > 1e-9:
        errors.append(f"{name} shares sum to {total:.6f}, expected 1.0")
    for key, value in shares.items():
        if value < 0:
            errors.append(f"{name}.{key} has negative share {value}")
    return errors


def _source_status(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    status: dict[str, dict[str, Any]] = {}
    for name, rel_path in config["source_baseline"].items():
        path = ROOT / rel_path
        item: dict[str, Any] = {
            "path": rel_path,
            "exists": path.exists(),
        }
        if path.exists():
            item["bytes"] = path.stat().st_size
        status[name] = item
    return status


def build_dry_run_report(config: dict[str, Any], *, batch: str) -> dict[str, Any]:
    if batch not in config["targets"]:
        raise ValueError(f"unknown batch {batch!r}; expected one of {sorted(config['targets'])}")

    errors: list[str] = []
    errors.extend(
        _validate_share_block(
            "sft_distribution.primary_category_share",
            config["sft_distribution"]["primary_category_share"],
        )
    )
    errors.extend(
        _validate_share_block(
            "sft_distribution.split_share",
            config["sft_distribution"]["split_share"],
        )
    )
    errors.extend(
        _validate_share_block(
            "sft_distribution.severity_share",
            config["sft_distribution"]["severity_share"],
        )
    )
    errors.extend(
        _validate_share_block(
            "dpo_distribution.rejected_mode_share",
            config["dpo_distribution"]["rejected_mode_share"],
        )
    )

    source_status = _source_status(config)
    for name, item in source_status.items():
        if not item["exists"]:
            errors.append(f"source_baseline.{name} missing: {item['path']}")

    target = config["targets"][batch]
    sft_total = int(target["sft_records"])
    dpo_total = int(target["dpo_preference_pairs"])

    return {
        "version": config["version"],
        "mode": "dry_run",
        "batch": batch,
        "source_status": source_status,
        "targets": {
            "sft_records": sft_total,
            "dpo_preference_pairs": dpo_total,
        },
        "planned_counts": {
            "sft_primary_category": _largest_remainder_counts(
                sft_total, config["sft_distribution"]["primary_category_share"]
            ),
            "sft_split": _largest_remainder_counts(
                sft_total, config["sft_distribution"]["split_share"]
            ),
            "sft_severity": _largest_remainder_counts(
                sft_total, config["sft_distribution"]["severity_share"]
            ),
            "dpo_rejected_mode": _largest_remainder_counts(
                dpo_total, config["dpo_distribution"]["rejected_mode_share"]
            ),
        },
        "quality_gates": config["quality_gates"],
        "llm_as_judge_required_coverage": config["llm_as_judge"]["required_coverage"],
        "outputs": config["outputs"],
        "valid": not errors,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--batch", choices=["first_batch", "second_batch"], default="first_batch")
    parser.add_argument("--dry-run", action="store_true", help="Plan counts without writing training JSONL.")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    if not args.dry_run:
        raise SystemExit("Full generation is not enabled yet; run with --dry-run.")

    config = _load_json(args.config)
    report = build_dry_run_report(config, batch=args.batch)
    _write_json(args.report, report)

    print(f"Scale dry-run batch: {args.batch}")
    print(f"SFT target: {report['targets']['sft_records']}")
    print(f"DPO target: {report['targets']['dpo_preference_pairs']}")
    print(f"Valid: {report['valid']}")
    print(f"Report: {args.report}")
    if report["errors"]:
        for error in report["errors"]:
            print(f"  [ERROR] {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
