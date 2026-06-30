#!/usr/bin/env python3
"""Apply LLM-as-judge decisions to scaled Phase 1.5 assets."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SFT = ROOT / "training" / "phase15-sft-scaled-5200.jsonl"
DEFAULT_DPO = ROOT / "training" / "phase15-dpo-scaled-2600.jsonl"
DEFAULT_SFT_OUTPUT = ROOT / "training" / "phase15-sft-scaled-5200-judged.jsonl"
DEFAULT_DPO_OUTPUT = ROOT / "training" / "phase15-dpo-scaled-2600-judged.jsonl"
DEFAULT_DECISIONS = ROOT / "evaluation" / "review" / "phase15-llm-judge-decisions.jsonl"
DEFAULT_REPORT = ROOT / "evaluation" / "review" / "phase15-llm-judge-apply-report.json"
SCHEMA_PATH = ROOT / "schemas" / "training-record.schema.json"

APPROVE = "approve"
NEEDS_CHANGES = "needs_changes"
REJECT = "reject"
ESCALATE = "escalate_to_human"
VALID_DECISIONS = {APPROVE, NEEDS_CHANGES, REJECT, ESCALATE}
LLM_JUDGE_TAGS = {
    "llm_judge_approved",
    "llm_judge_incomplete",
    "llm_judge_needs_changes",
    "llm_judge_reject",
    "llm_judge_escalate_to_human",
}


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


def _load_decisions(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    decisions: dict[tuple[str, str], dict[str, Any]] = {}
    for record in _load_jsonl(path):
        asset_type = record.get("asset_type")
        sample_id = record.get("sample_id")
        if asset_type not in {"sft", "dpo"} or not sample_id:
            raise ValueError(f"{path}: judge decision requires asset_type=sft|dpo and sample_id")
        key = (asset_type, sample_id)
        if key in decisions:
            raise ValueError(f"{path}: duplicate judge decision for {asset_type}:{sample_id}")
        decision = record.get("judge_decision")
        if decision not in VALID_DECISIONS:
            raise ValueError(
                f"{path}: {asset_type}:{sample_id} judge_decision must be one of {sorted(VALID_DECISIONS)}"
            )
        decisions[key] = record
    return decisions


def _checklist_passed(decision: dict[str, Any]) -> bool:
    checklist = decision.get("checklist", {})
    if not isinstance(checklist, dict) or not checklist:
        return False
    return all(value is True for value in checklist.values())


def _set_tag(record: dict[str, Any], tag: str) -> None:
    quality = record.setdefault("quality", {})
    tags = quality.setdefault("tags", [])
    quality["tags"] = [existing for existing in tags if existing not in LLM_JUDGE_TAGS]
    if tag not in quality["tags"]:
        quality["tags"].append(tag)


def _metadata(decision: dict[str, Any], applied_status: str, checklist_passed: bool) -> dict[str, Any]:
    return {
        "decision": decision["judge_decision"],
        "applied_status": applied_status,
        "judge_model": decision.get("judge_model", ""),
        "judged_at": decision.get("judged_at", ""),
        "notes": decision.get("notes", ""),
        "checklist": decision.get("checklist", {}),
        "checklist_passed": checklist_passed,
    }


def _apply_to_records(
    records: list[dict[str, Any]],
    decisions: dict[tuple[str, str], dict[str, Any]],
    *,
    asset_type: str,
) -> tuple[list[dict[str, Any]], Counter[str]]:
    summary: Counter[str] = Counter()
    output: list[dict[str, Any]] = []
    for record in records:
        sample_id = record["sample_id"]
        decision = decisions.get((asset_type, sample_id))
        if decision is None:
            summary["unchanged_no_decision"] += 1
            output.append(record)
            continue

        judge_decision = decision["judge_decision"]
        judge_model = decision.get("judge_model", "").strip()
        judged_at = decision.get("judged_at", "").strip()
        checklist_passed = _checklist_passed(decision)
        quality = record.setdefault("quality", {})

        if judge_decision == APPROVE and judge_model and judged_at and checklist_passed:
            applied_status = "llm_judge_approved"
            summary["llm_judge_approved"] += 1
        elif judge_decision == APPROVE:
            applied_status = "llm_judge_incomplete"
            summary["llm_judge_incomplete"] += 1
        elif judge_decision == NEEDS_CHANGES:
            applied_status = "llm_judge_needs_changes"
            summary["llm_judge_needs_changes"] += 1
        elif judge_decision == REJECT:
            applied_status = "llm_judge_reject"
            summary["llm_judge_reject"] += 1
        else:
            applied_status = "llm_judge_escalate_to_human"
            summary["llm_judge_escalate_to_human"] += 1

        quality["llm_judge"] = _metadata(decision, applied_status, checklist_passed)
        _set_tag(record, applied_status)
        output.append(record)
    return output, summary


def _schema_errors(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors: list[dict[str, Any]] = []
    for line_no, record in enumerate(records, start=1):
        for error in validator.iter_errors(record):
            errors.append(
                {
                    "line": line_no,
                    "sample_id": record.get("sample_id"),
                    "message": error.message,
                    "path": list(error.path),
                }
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sft", type=Path, default=DEFAULT_SFT)
    parser.add_argument("--dpo", type=Path, default=DEFAULT_DPO)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--sft-output", type=Path, default=DEFAULT_SFT_OUTPUT)
    parser.add_argument("--dpo-output", type=Path, default=DEFAULT_DPO_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    decisions = _load_decisions(args.decisions)
    sft_records, sft_summary = _apply_to_records(
        _load_jsonl(args.sft), decisions, asset_type="sft"
    )
    dpo_records, dpo_summary = _apply_to_records(
        _load_jsonl(args.dpo), decisions, asset_type="dpo"
    )

    known_keys = {
        ("sft", record["sample_id"]) for record in sft_records
    } | {
        ("dpo", record["sample_id"]) for record in dpo_records
    }
    unknown = sorted(f"{asset}:{sample_id}" for asset, sample_id in set(decisions) - known_keys)
    schema_errors = {
        "sft": _schema_errors(sft_records),
        "dpo": _schema_errors(dpo_records),
    }
    report = {
        "input": {
            "sft": str(args.sft),
            "dpo": str(args.dpo),
            "decisions": str(args.decisions),
        },
        "output": {
            "sft": str(args.sft_output),
            "dpo": str(args.dpo_output),
        },
        "dry_run": args.dry_run,
        "summary": {
            "sft": dict(sft_summary),
            "dpo": dict(dpo_summary),
            "decisions": len(decisions),
            "unknown_decisions": len(unknown),
        },
        "unknown_decision_ids": unknown,
        "schema_valid": not schema_errors["sft"] and not schema_errors["dpo"],
        "schema_errors": schema_errors,
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if not report["schema_valid"]:
        print("Schema valid: False")
        print(f"Report: {args.report}")
        return 1

    if not args.dry_run:
        _write_jsonl(args.sft_output, sft_records)
        _write_jsonl(args.dpo_output, dpo_records)

    print(f"LLM judge decisions applied: {len(decisions)}")
    print(f"SFT approved: {sft_summary.get('llm_judge_approved', 0)}")
    print(f"DPO approved: {dpo_summary.get('llm_judge_approved', 0)}")
    print(f"Schema valid: {report['schema_valid']}")
    print(f"Report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
