#!/usr/bin/env python3
"""Export pending Phase 1.5 SFT samples into a human-review queue."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SFT = ROOT / "training" / "phase15-sft-bootstrap.jsonl"
DEFAULT_QUEUE = ROOT / "evaluation" / "review" / "phase15-sft-review-queue.jsonl"
DEFAULT_DECISIONS_TEMPLATE = ROOT / "evaluation" / "review" / "phase15-sft-review-decisions.template.jsonl"


REVIEW_CHECKLIST = [
    "primary_category and secondary_categories match the dominant risk",
    "risk_ids are specific, complete, and traceable to taxonomy/risk-taxonomy.v1.yaml",
    "severity is not downgraded for high/critical or tool-action risk",
    "decision is acceptable under taxonomy/policy-to-decision-mapping.v1.yaml",
    "control_actions include required audit, redaction, escalation, or tool blocking controls",
    "audit_required and human_review_required match severity, authority, and risk surface",
    "recommended_safe_response avoids leakage, unsafe details, and over-refusal",
    "prompt variant preserves the original P0 scenario semantics",
]


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def _review_item(record: dict) -> dict:
    labels = record["labels"]
    expected = record["expected_output"]
    return {
        "sample_id": record["sample_id"],
        "split": record["split"],
        "difficulty": record.get("quality", {}).get("difficulty"),
        "review_status": record.get("quality", {}).get("review_status", "missing"),
        "input": record["input"],
        "labels": labels,
        "expected_output": expected,
        "review_checklist": REVIEW_CHECKLIST,
        "review_decision_template": {
            "sample_id": record["sample_id"],
            "review_decision": "approve",
            "reviewer": "",
            "reviewed_at": "",
            "notes": "",
            "checklist": {
                "taxonomy_match": True,
                "decision_correct": True,
                "controls_complete": True,
                "audit_flags_correct": True,
                "safe_response_acceptable": True,
            },
        },
    }


def _decision_template(record: dict) -> dict:
    return {
        "sample_id": record["sample_id"],
        "review_decision": "approve",
        "reviewer": "",
        "reviewed_at": "",
        "notes": "",
        "checklist": {
            "taxonomy_match": True,
            "decision_correct": True,
            "controls_complete": True,
            "audit_flags_correct": True,
            "safe_response_acceptable": True,
        },
    }


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sft", type=Path, default=DEFAULT_SFT)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--decisions-template", type=Path, default=DEFAULT_DECISIONS_TEMPLATE)
    parser.add_argument("--status", default="pending_human_review")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    records = [
        record
        for record in _load_jsonl(args.sft)
        if record.get("quality", {}).get("review_status") == args.status
    ]
    if args.limit is not None:
        records = records[: args.limit]

    _write_jsonl(args.queue, [_review_item(record) for record in records])
    _write_jsonl(args.decisions_template, [_decision_template(record) for record in records])

    print(f"Exported review queue: {len(records)} samples")
    print(f"Queue: {args.queue}")
    print(f"Decisions template: {args.decisions_template}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
