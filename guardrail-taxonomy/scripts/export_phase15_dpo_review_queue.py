#!/usr/bin/env python3
"""Export Phase 1.5 DPO preference pairs into a human-review queue."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DPO = ROOT / "training" / "phase15-dpo-preference-bootstrap.jsonl"
DEFAULT_QUEUE = ROOT / "evaluation" / "review" / "phase15-dpo-review-queue.jsonl"
DEFAULT_DECISIONS_TEMPLATE = (
    ROOT / "evaluation" / "review" / "phase15-dpo-review-decisions.template.jsonl"
)
DEFAULT_DECISIONS = ROOT / "evaluation" / "review" / "phase15-dpo-review-decisions.jsonl"

REVIEW_CHECKLIST = [
    "chosen output is policy-superior to rejected output",
    "chosen preserves correct decision, risk IDs, severity, controls, and safe response",
    "rejected output demonstrates the stated negative mode without becoming ambiguous",
    "negative mode is useful for preference learning and not a duplicate of chosen",
    "audit/review flags and release gate impact remain policy-aligned",
]


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def _dpo_mode(record: dict) -> str:
    evidence = record["rejected"]["evidence"][0]["value"]
    return evidence.split(" candidate for ", maxsplit=1)[0]


def _review_status(record: dict) -> str:
    return record.get("quality", {}).get("review_status", "pending_human_review")


def _eligible(record: dict, status: str) -> bool:
    if status == "any":
        return True
    return _review_status(record) == status


def _decision_template(record: dict, *, default_reviewer: str = "") -> dict:
    return {
        "sample_id": record["sample_id"],
        "review_decision": "approve",
        "reviewer": default_reviewer,
        "reviewed_at": "",
        "notes": "",
        "checklist": {
            "chosen_preferred": True,
            "chosen_policy_correct": True,
            "rejected_negative_mode_clear": True,
            "preference_signal_useful": True,
            "audit_flags_correct": True,
        },
    }


def _review_item(record: dict, *, default_reviewer: str = "") -> dict:
    return {
        "sample_id": record["sample_id"],
        "review_status": _review_status(record),
        "negative_mode": _dpo_mode(record),
        "input": record["input"],
        "chosen": record["chosen"],
        "rejected": record["rejected"],
        "preference_reason": record["preference_reason"],
        "review_checklist": REVIEW_CHECKLIST,
        "review_decision_template": _decision_template(
            record, default_reviewer=default_reviewer
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dpo", type=Path, default=DEFAULT_DPO)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--decisions-template", type=Path, default=DEFAULT_DECISIONS_TEMPLATE)
    parser.add_argument(
        "--decisions",
        type=Path,
        default=None,
        help="Optional working decisions file for the reviewer to fill in",
    )
    parser.add_argument(
        "--default-reviewer",
        default="",
        help="Pre-fill reviewer in exported decision templates",
    )
    parser.add_argument(
        "--status",
        default="pending_human_review",
        help="Review status to export; use 'any' to export all records",
    )
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    records = [record for record in _load_jsonl(args.dpo) if _eligible(record, args.status)]
    if args.limit is not None:
        records = records[: args.limit]

    reviewer = args.default_reviewer.strip()
    queue_items = [_review_item(record, default_reviewer=reviewer) for record in records]
    decision_items = [
        _decision_template(record, default_reviewer=reviewer) for record in records
    ]

    _write_jsonl(args.queue, queue_items)
    _write_jsonl(args.decisions_template, decision_items)
    if args.decisions is not None:
        _write_jsonl(args.decisions, decision_items)

    print(f"Exported DPO review queue: {len(records)} preference pairs")
    if reviewer:
        print(f"Default reviewer: {reviewer}")
    print(f"Queue: {args.queue}")
    print(f"Decisions template: {args.decisions_template}")
    if args.decisions is not None:
        print(f"Decisions working file: {args.decisions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
