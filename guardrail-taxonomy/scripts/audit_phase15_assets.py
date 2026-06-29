#!/usr/bin/env python3
"""Audit Phase 1.5 bootstrap datasets for schema validity and coverage."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SFT = ROOT / "training" / "phase15-sft-bootstrap.jsonl"
DEFAULT_DPO = ROOT / "training" / "phase15-dpo-preference-bootstrap.jsonl"
DEFAULT_REPORT = ROOT / "evaluation" / "phase15-quality-report.json"
SCHEMA_PATH = ROOT / "schemas" / "training-record.schema.json"

MIN_SFT_RECORDS = 100
MIN_DPO_PAIRS = 50
REQUIRED_SFT_SPLITS = {"train", "val", "test"}
REQUIRED_CATEGORIES = {"SEC", "PRI", "SAF", "REL"}
REQUIRED_DPO_MODES = {"unsafe_allow", "over_refusal", "missing_audit"}
REVIEW_STATE_TAGS = {
    "human_reviewed",
    "review_incomplete",
    "review_reject",
    "review_needs_changes",
}


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return records


def _schema_errors(records: list[dict], validator: Draft202012Validator) -> list[dict]:
    errors: list[dict] = []
    for index, record in enumerate(records, start=1):
        for error in validator.iter_errors(record):
            errors.append(
                {
                    "line": index,
                    "sample_id": record.get("sample_id"),
                    "message": error.message,
                    "path": list(error.path),
                }
            )
    return errors


def _duplicates(values: list[str]) -> list[str]:
    counts = Counter(values)
    return sorted(value for value, count in counts.items() if count > 1)


def _dpo_mode(record: dict) -> str:
    evidence = record["rejected"]["evidence"][0]["value"]
    return evidence.split(" candidate for ", maxsplit=1)[0]


def build_report(sft_records: list[dict], dpo_records: list[dict]) -> dict:
    sft_ids = [record["sample_id"] for record in sft_records]
    dpo_ids = [record["sample_id"] for record in dpo_records]

    split_counts = Counter(record["split"] for record in sft_records)
    category_counts = Counter(record["labels"]["primary_category"] for record in sft_records)
    decision_counts = Counter(record["labels"]["decision"] for record in sft_records)
    risk_id_counts = Counter(
        risk_id for record in sft_records for risk_id in record["labels"]["risk_ids"]
    )
    review_status_counts = Counter(
        record.get("quality", {}).get("review_status", "missing") for record in sft_records
    )
    review_state_conflicts = []
    for record in sft_records:
        quality = record.get("quality", {})
        status = quality.get("review_status")
        tags = set(quality.get("tags", []))
        state_tags = sorted(tags & REVIEW_STATE_TAGS)
        if status == "human_reviewed" and any(tag != "human_reviewed" for tag in state_tags):
            review_state_conflicts.append(record["sample_id"])
        if status == "pending_human_review" and "human_reviewed" in state_tags:
            review_state_conflicts.append(record["sample_id"])
    dpo_modes = Counter(_dpo_mode(record) for record in dpo_records)

    gates = {
        "sft_min_records": len(sft_records) >= MIN_SFT_RECORDS,
        "dpo_min_pairs": len(dpo_records) >= MIN_DPO_PAIRS,
        "sft_has_train_val_test": REQUIRED_SFT_SPLITS.issubset(split_counts),
        "sft_has_all_primary_categories": REQUIRED_CATEGORIES.issubset(category_counts),
        "dpo_has_required_negative_modes": REQUIRED_DPO_MODES.issubset(dpo_modes),
        "no_duplicate_sample_ids": not _duplicates(sft_ids + dpo_ids),
        "no_review_state_conflicts": not review_state_conflicts,
    }

    return {
        "version": "1.5.0",
        "inputs": {
            "sft_records": len(sft_records),
            "dpo_preference_pairs": len(dpo_records),
        },
        "coverage": {
            "sft_split_counts": dict(sorted(split_counts.items())),
            "primary_category_counts": dict(sorted(category_counts.items())),
            "decision_counts": dict(sorted(decision_counts.items())),
            "risk_id_counts": dict(sorted(risk_id_counts.items())),
            "review_status_counts": dict(sorted(review_status_counts.items())),
            "dpo_rejected_modes": dict(sorted(dpo_modes.items())),
        },
        "integrity": {
            "duplicate_sample_ids": _duplicates(sft_ids + dpo_ids),
            "review_state_conflict_sample_ids": review_state_conflicts,
        },
        "quality_gates": gates,
        "passed": all(gates.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sft", type=Path, default=DEFAULT_SFT)
    parser.add_argument("--dpo", type=Path, default=DEFAULT_DPO)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    sft_records = _load_jsonl(args.sft)
    dpo_records = _load_jsonl(args.dpo)
    schema_errors = {
        "sft": _schema_errors(sft_records, validator),
        "dpo": _schema_errors(dpo_records, validator),
    }

    report = build_report(sft_records, dpo_records)
    report["schema"] = {
        "valid": not schema_errors["sft"] and not schema_errors["dpo"],
        "errors": schema_errors,
    }
    report["passed"] = report["passed"] and report["schema"]["valid"]

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"SFT records: {len(sft_records)}")
    print(f"DPO pairs: {len(dpo_records)}")
    print(f"Schema valid: {report['schema']['valid']}")
    print(f"Quality gates: {'PASS' if report['passed'] else 'FAIL'}")
    print(f"Report: {args.report}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
