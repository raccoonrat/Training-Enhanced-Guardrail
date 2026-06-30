#!/usr/bin/env python3
"""Export scaled Phase 1.5 assets for LLM-as-judge secondary review."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "evaluation" / "phase15-scale-config.json"
DEFAULT_SFT = ROOT / "training" / "phase15-sft-scaled-5200.jsonl"
DEFAULT_DPO = ROOT / "training" / "phase15-dpo-scaled-2600.jsonl"
DEFAULT_QUEUE = ROOT / "evaluation" / "review" / "phase15-llm-judge-queue.jsonl"
DEFAULT_DECISIONS_TEMPLATE = (
    ROOT / "evaluation" / "review" / "phase15-llm-judge-decisions.template.jsonl"
)
DEFAULT_DECISIONS = ROOT / "evaluation" / "review" / "phase15-llm-judge-decisions.jsonl"
DEFAULT_REPORT = ROOT / "evaluation" / "review" / "phase15-llm-judge-queue-report.json"

JUDGE_CHECKLIST = {
    "taxonomy_match": True,
    "severity_justified": True,
    "decision_controls_policy_aligned": True,
    "safe_response_non_leaking_non_enabling": True,
    "dpo_rejected_mode_clear_if_applicable": True,
    "no_hidden_actionability": True,
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return records


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _stable_score(value: str) -> float:
    raw = int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:16], 16)
    return raw / float(0xFFFFFFFFFFFFFFFF)


def _dpo_mode(record: dict[str, Any]) -> str:
    evidence = record["rejected"]["evidence"][0]["value"]
    return evidence.split(" candidate for ", maxsplit=1)[0]


def _sft_reasons(record: dict[str, Any], coverage: dict[str, float]) -> list[str]:
    reasons: list[str] = []
    severity = record["labels"]["severity"]
    metadata = record["input"].get("metadata", {})
    if severity == "critical":
        reasons.append("critical:100%")
    if metadata.get("scale_tool_variant") == "destructive_tool":
        reasons.append("destructive_tool_surface:100%")
    score = _stable_score(f"sft:{severity}:{record['sample_id']}")
    if severity == "high" and score < coverage["high_stratified_sample"]:
        reasons.append("high_stratified_sample:20%")
    if severity in {"medium", "low"} and score < coverage["medium_low_stratified_sample"]:
        reasons.append("medium_low_stratified_sample:10%")
    return reasons


def _dpo_reasons(record: dict[str, Any], coverage: dict[str, float]) -> list[str]:
    reasons: list[str] = []
    severity = record["chosen"]["severity"]
    mode = _dpo_mode(record)
    if severity == "critical":
        reasons.append("critical:100%")
    if mode == "wrong_category":
        reasons.append("dpo_wrong_category:100%")
    if mode == "weak_safe_response":
        reasons.append("dpo_weak_safe_response:100%")
    score = _stable_score(f"dpo:{severity}:{mode}:{record['sample_id']}")
    if severity == "high" and score < coverage["high_stratified_sample"]:
        reasons.append("high_stratified_sample:20%")
    if severity in {"medium", "low"} and score < coverage["medium_low_stratified_sample"]:
        reasons.append("medium_low_stratified_sample:10%")
    return reasons


def _decision_template(asset_type: str, sample_id: str) -> dict[str, Any]:
    return {
        "asset_type": asset_type,
        "sample_id": sample_id,
        "judge_decision": "approve",
        "judge_model": "",
        "judged_at": "",
        "notes": "",
        "checklist": dict(JUDGE_CHECKLIST),
    }


def _sft_item(record: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    return {
        "asset_type": "sft",
        "sample_id": record["sample_id"],
        "split": record["split"],
        "judge_reasons": reasons,
        "input": record["input"],
        "labels": record["labels"],
        "expected_output": record["expected_output"],
        "quality": record.get("quality", {}),
        "judge_checklist": list(JUDGE_CHECKLIST),
        "judge_decision_template": _decision_template("sft", record["sample_id"]),
    }


def _dpo_item(record: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    return {
        "asset_type": "dpo",
        "sample_id": record["sample_id"],
        "negative_mode": _dpo_mode(record),
        "judge_reasons": reasons,
        "input": record["input"],
        "chosen": record["chosen"],
        "rejected": record["rejected"],
        "preference_reason": record["preference_reason"],
        "quality": record.get("quality", {}),
        "judge_checklist": list(JUDGE_CHECKLIST),
        "judge_decision_template": _decision_template("dpo", record["sample_id"]),
    }


def build_queue(
    sft_records: list[dict[str, Any]],
    dpo_records: list[dict[str, Any]],
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    coverage = config["llm_as_judge"]["required_coverage"]
    queue: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()

    for record in sft_records:
        reasons = _sft_reasons(record, coverage)
        if not reasons:
            continue
        queue.append(_sft_item(record, reasons))
        decisions.append(_decision_template("sft", record["sample_id"]))
        reason_counts.update(f"sft:{reason}" for reason in reasons)

    for record in dpo_records:
        reasons = _dpo_reasons(record, coverage)
        if not reasons:
            continue
        queue.append(_dpo_item(record, reasons))
        decisions.append(_decision_template("dpo", record["sample_id"]))
        reason_counts.update(f"dpo:{reason}" for reason in reasons)

    summary = {
        "queue_items": len(queue),
        "sft_items": sum(1 for item in queue if item["asset_type"] == "sft"),
        "dpo_items": sum(1 for item in queue if item["asset_type"] == "dpo"),
        "reason_counts": dict(sorted(reason_counts.items())),
    }
    return queue, decisions, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--sft", type=Path, default=DEFAULT_SFT)
    parser.add_argument("--dpo", type=Path, default=DEFAULT_DPO)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--decisions-template", type=Path, default=DEFAULT_DECISIONS_TEMPLATE)
    parser.add_argument("--decisions", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    config = _load_json(args.config)
    queue, decisions, summary = build_queue(
        _load_jsonl(args.sft),
        _load_jsonl(args.dpo),
        config,
    )
    _write_jsonl(args.queue, queue)
    _write_jsonl(args.decisions_template, decisions)
    if args.decisions is not None:
        _write_jsonl(args.decisions, decisions)
    _write_json(
        args.report,
        {
            "input": {
                "sft": str(args.sft),
                "dpo": str(args.dpo),
                "config": str(args.config),
            },
            "outputs": {
                "queue": str(args.queue),
                "decisions_template": str(args.decisions_template),
                "decisions": str(args.decisions) if args.decisions is not None else None,
            },
            "summary": summary,
        },
    )

    print(f"Exported LLM judge queue: {summary['queue_items']} items")
    print(f"SFT items: {summary['sft_items']}")
    print(f"DPO items: {summary['dpo_items']}")
    print(f"Queue: {args.queue}")
    print(f"Decisions template: {args.decisions_template}")
    if args.decisions is not None:
        print(f"Decisions working file: {args.decisions}")
    print(f"Report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
