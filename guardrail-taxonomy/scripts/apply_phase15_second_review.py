#!/usr/bin/env python3
"""Apply independent second-review decisions to Phase 1.5 SFT records."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SFT = ROOT / "training" / "phase15-sft-reviewed.jsonl"
DEFAULT_OUTPUT = ROOT / "training" / "phase15-sft-reviewed-second.jsonl"
DEFAULT_DECISIONS = ROOT / "evaluation" / "review" / "phase15-sft-second-review-decisions.jsonl"
DEFAULT_REPORT = ROOT / "evaluation" / "review" / "phase15-second-review-apply-report.json"
SCHEMA_PATH = ROOT / "schemas" / "training-record.schema.json"

APPROVE = "approve"
CHALLENGE = "challenge"
NEEDS_CHANGES = "needs_changes"
VALID_DECISIONS = {APPROVE, CHALLENGE, NEEDS_CHANGES}
SECOND_REVIEW_TAGS = {
    "second_reviewed",
    "second_review_incomplete",
    "second_review_challenge",
    "second_review_needs_changes",
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


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def _load_decisions(path: Path) -> dict[str, dict]:
    decisions: dict[str, dict] = {}
    for record in _load_jsonl(path):
        sample_id = record.get("sample_id")
        if not sample_id:
            raise ValueError(f"{path}: second-review decision missing sample_id")
        if sample_id in decisions:
            raise ValueError(f"{path}: duplicate second-review decision for {sample_id}")
        decision = record.get("second_review_decision")
        if decision not in VALID_DECISIONS:
            raise ValueError(
                f"{path}: {sample_id} second_review_decision must be one of {sorted(VALID_DECISIONS)}"
            )
        decisions[sample_id] = record
    return decisions


def _checklist_passed(decision: dict) -> bool:
    checklist = decision.get("checklist", {})
    if not isinstance(checklist, dict) or not checklist:
        return False
    return all(value is True for value in checklist.values())


def _set_second_review_tag(record: dict, tag: str) -> None:
    quality = record.setdefault("quality", {})
    tags = quality.setdefault("tags", [])
    quality["tags"] = [existing for existing in tags if existing not in SECOND_REVIEW_TAGS]
    if tag not in quality["tags"]:
        quality["tags"].append(tag)


def _metadata(decision: dict, applied_status: str, independent: bool) -> dict:
    reviewed_at = decision.get("reviewed_at") or datetime.now(UTC).isoformat()
    return {
        "decision": decision["second_review_decision"],
        "applied_status": applied_status,
        "reviewer": decision.get("reviewer", ""),
        "reviewed_at": reviewed_at,
        "notes": decision.get("notes", ""),
        "independent_reviewer": independent,
        "checklist": decision.get("checklist", {}),
    }


def _first_reviewer(record: dict) -> str:
    return record.get("quality", {}).get("review", {}).get("reviewer", "").strip()


def apply_second_reviews(
    records: list[dict],
    decisions: dict[str, dict],
    *,
    allow_same_reviewer: bool = False,
) -> tuple[list[dict], dict]:
    summary = Counter()
    output: list[dict] = []

    for record in records:
        sample_id = record["sample_id"]
        decision = decisions.get(sample_id)
        if decision is None:
            summary["unchanged_no_decision"] += 1
            output.append(record)
            continue

        second_decision = decision["second_review_decision"]
        reviewer = decision.get("reviewer", "").strip()
        first_reviewer = _first_reviewer(record)
        independent = bool(reviewer) and (allow_same_reviewer or reviewer != first_reviewer)
        checklist_passed = _checklist_passed(decision)
        quality = record.setdefault("quality", {})

        if second_decision == APPROVE and not decision.get("reviewed_at", "").strip():
            raise ValueError(
                f"{sample_id}: second_review_decision=approve requires non-empty reviewed_at"
            )

        if second_decision == APPROVE and independent and checklist_passed:
            quality["second_review"] = _metadata(decision, "second_reviewed", independent)
            _set_second_review_tag(record, "second_reviewed")
            summary["second_reviewed"] += 1
        elif second_decision == APPROVE:
            quality["second_review"] = _metadata(decision, "second_review_incomplete", independent)
            _set_second_review_tag(record, "second_review_incomplete")
            summary["approve_incomplete"] += 1
        else:
            applied_status = f"second_review_{second_decision}"
            quality["second_review"] = _metadata(decision, applied_status, independent)
            _set_second_review_tag(record, applied_status)
            summary[second_decision] += 1

        output.append(record)

    unknown_decisions = sorted(set(decisions) - {record["sample_id"] for record in records})
    summary["unknown_decisions"] = len(unknown_decisions)
    return output, {"summary": dict(summary), "unknown_decision_sample_ids": unknown_decisions}


def _schema_errors(records: list[dict]) -> list[dict]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors: list[dict] = []
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
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dry-run", action="store_true", help="Validate and report without writing output.")
    parser.add_argument("--allow-same-reviewer", action="store_true")
    args = parser.parse_args()

    records = _load_jsonl(args.sft)
    decisions = _load_decisions(args.decisions)
    reviewed_records, report = apply_second_reviews(
        records,
        decisions,
        allow_same_reviewer=args.allow_same_reviewer,
    )
    errors = _schema_errors(reviewed_records)
    report.update(
        {
            "input": str(args.sft),
            "decisions": str(args.decisions),
            "output": str(args.output),
            "dry_run": args.dry_run,
            "schema_valid": not errors,
            "schema_errors": errors,
        }
    )

    if errors:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("Schema valid: False")
        print(f"Report: {args.report}")
        return 1

    if not args.dry_run:
        _write_jsonl(args.output, reviewed_records)

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"Second-review decisions applied: {len(decisions)}")
    print(f"Second reviewed: {report['summary'].get('second_reviewed', 0)}")
    print(f"Schema valid: {report['schema_valid']}")
    print(f"Output: {report['output']}")
    print(f"Report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
