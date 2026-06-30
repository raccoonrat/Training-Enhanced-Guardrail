#!/usr/bin/env python3
"""Export high-risk Phase 1.5 SFT samples for independent second review."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SFT = ROOT / "training" / "phase15-sft-reviewed.jsonl"
DEFAULT_QUEUE = ROOT / "evaluation" / "review" / "phase15-sft-second-review-queue.jsonl"
DEFAULT_DECISIONS_TEMPLATE = (
    ROOT / "evaluation" / "review" / "phase15-sft-second-review-decisions.template.jsonl"
)
DEFAULT_DECISIONS = ROOT / "evaluation" / "review" / "phase15-sft-second-review-decisions.jsonl"

SECOND_REVIEW_CHECKLIST = [
    "second reviewer is independent from the first reviewer",
    "high/critical severity is justified and not over- or under-labeled",
    "REL cases correctly handle uncertainty, evidence, citation, and tool-result risks",
    "decision and control_actions remain policy-aligned after independent review",
    "safe response is non-leaking, non-enabling, and not over-refusing benign content",
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


def _second_review_reasons(record: dict) -> list[str]:
    labels = record["labels"]
    reasons: list[str] = []
    if labels["severity"] in {"high", "critical"}:
        reasons.append(f"severity:{labels['severity']}")
    if labels["primary_category"] == "REL":
        reasons.append("primary_category:REL")
    if record.get("quality", {}).get("review", {}).get("reviewer"):
        reasons.append("first_review_completed")
    return reasons


def _eligible(record: dict) -> bool:
    quality = record.get("quality", {})
    labels = record["labels"]
    if quality.get("review_status") != "human_reviewed":
        return False
    return labels["severity"] in {"high", "critical"} or labels["primary_category"] == "REL"


def _eligible_challenged(record: dict) -> bool:
    second_review = record.get("quality", {}).get("second_review", {})
    return second_review.get("applied_status") == "second_review_challenge"


def _decision_template(record: dict, *, default_reviewer: str = "") -> dict:
    return {
        "sample_id": record["sample_id"],
        "second_review_decision": "approve",
        "reviewer": default_reviewer,
        "reviewed_at": "",
        "notes": "",
        "checklist": {
            "independent_reviewer": True,
            "severity_justified": True,
            "taxonomy_match": True,
            "decision_correct": True,
            "controls_complete": True,
            "safe_response_acceptable": True,
        },
    }


def _review_item(record: dict, *, default_reviewer: str = "") -> dict:
    first_review = record.get("quality", {}).get("review", {})
    return {
        "sample_id": record["sample_id"],
        "split": record["split"],
        "first_reviewer": first_review.get("reviewer", ""),
        "second_review_reasons": _second_review_reasons(record),
        "input": record["input"],
        "labels": record["labels"],
        "expected_output": record["expected_output"],
        "first_review": first_review,
        "second_review_checklist": SECOND_REVIEW_CHECKLIST,
        "second_review_decision_template": _decision_template(
            record, default_reviewer=default_reviewer
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sft", type=Path, default=DEFAULT_SFT)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--decisions-template", type=Path, default=DEFAULT_DECISIONS_TEMPLATE)
    parser.add_argument(
        "--decisions",
        type=Path,
        default=None,
        help="Optional working decisions file for the second reviewer to fill in",
    )
    parser.add_argument(
        "--default-reviewer",
        default="",
        help="Pre-fill reviewer in exported decision templates (e.g. wyh)",
    )
    parser.add_argument(
        "--only-challenged",
        action="store_true",
        help="Export only samples previously marked second_review_challenge",
    )
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    all_records = _load_jsonl(args.sft)
    if args.only_challenged:
        records = [record for record in all_records if _eligible_challenged(record)]
    else:
        records = [record for record in all_records if _eligible(record)]
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

    mode = "challenged" if args.only_challenged else "policy-selected"
    print(f"Exported second-review queue: {len(records)} samples ({mode})")
    if reviewer:
        print(f"Default reviewer: {reviewer}")
    print(f"Queue: {args.queue}")
    print(f"Decisions template: {args.decisions_template}")
    if args.decisions is not None:
        print(f"Decisions working file: {args.decisions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
