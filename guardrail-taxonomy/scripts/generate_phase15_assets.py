#!/usr/bin/env python3
"""Generate Phase 1.5 bootstrap training assets.

Phase 1 keeps the hand-authored P0 seed set small and stable. This script derives
deterministic, schema-valid SFT variants and DPO preference pairs from that seed
set so the next phase has enough data volume to test post-training pipelines
without changing the release-gate benchmark.
"""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from generate_phase1_assets import P0_CASES, training_record, write_jsonl

ROOT = Path(__file__).resolve().parents[1]
TRAINING = ROOT / "training"
EVALUATION = ROOT / "evaluation"


VARIANT_SUFFIXES = (
    ("v0", None),
    ("v1", "Please assess the guardrail decision for this enterprise workflow: {message}"),
    ("v2", "In a customer support setting, decide the safest policy action. Request: {message}"),
    ("v3", "Before any tool or answer is allowed, classify this request: {message}"),
)


def _case_family(case: dict) -> str:
    if case["category"] == "benign":
        return "benign"
    return case["expected_primary_category"].lower()


def _difficulty(case: dict, variant_suffix: str) -> str:
    if case["expected_severity"] in {"critical", "high"} and variant_suffix in {"v2", "v3"}:
        return "hard"
    if variant_suffix == "v0":
        return "easy"
    return "medium"


def _variant_case(case: dict, variant_suffix: str, prompt_template: str | None) -> dict:
    variant = deepcopy(case)
    variant["source_case_id"] = case["case_id"]
    variant["case_id"] = f"{case['case_id']}-{variant_suffix.upper()}"
    if prompt_template is not None:
        variant["user_message"] = prompt_template.format(message=case["user_message"])
        variant["evidence"] = [
            {
                "type": "prompt_variant",
                "value": f"{case['case_id']} rewritten as {variant_suffix}",
            }
        ] + case.get("evidence", [])
    return variant


def _phase15_sft_record(case: dict, variant_suffix: str) -> dict:
    record = training_record(case)
    base_id = case.get("source_case_id", case["case_id"]).lower()
    record["sample_id"] = f"phase15-sft-{base_id}-{variant_suffix}"
    record["quality"] = {
        "source": "phase15_deterministic_expansion",
        "review_status": "pending_human_review",
        "difficulty": _difficulty(case, variant_suffix),
        "tags": ["phase1.5", "sft", _case_family(case), variant_suffix],
    }
    return record


def _rejected_output(chosen: dict, mode: str, case: dict) -> dict:
    rejected = deepcopy(chosen)
    rejected["confidence"] = 0.55

    if mode == "unsafe_allow":
        rejected.update(
            {
                "decision": "allow",
                "primary_category": "REL",
                "secondary_categories": [],
                "risk_ids": ["REL-3.1"],
                "severity": "low",
                "control_actions": ["allow"],
                "recommended_safe_response": "The request can proceed without additional controls.",
                "audit_required": False,
                "human_review_required": False,
                "release_gate_impact": "none",
            }
        )
    elif mode == "over_refusal":
        rejected.update(
            {
                "decision": "refuse",
                "severity": "medium",
                "control_actions": ["safe_complete", "log_only"],
                "recommended_safe_response": "I cannot help with this request.",
                "audit_required": True,
                "human_review_required": False,
                "release_gate_impact": "warning",
            }
        )
    elif mode == "missing_audit":
        rejected["audit_required"] = False
        rejected["human_review_required"] = False
        rejected["control_actions"] = [
            action for action in rejected["control_actions"] if action not in {"log_only", "escalate"}
        ] or ["safe_complete"]
        rejected["recommended_safe_response"] = (
            "The action is constrained but lacks the required audit and review controls."
        )
    else:
        raise ValueError(f"unknown rejected mode: {mode}")

    rejected["evidence"] = [
        {
            "type": "preference_negative",
            "value": f"{mode} candidate for {case['case_id']}",
        }
    ]
    return rejected


def _dpo_pair(case: dict, index: int, mode: str) -> dict:
    chosen = training_record(case)["expected_output"]
    return {
        "sample_id": f"phase15-dpo-{case['case_id'].lower()}-{index:02d}",
        "schema_version": "1.0.0",
        "task_type": "guardrail_preference_pair",
        "input": {
            "user_message": case["user_message"],
            "risk_surface": case["risk_surface"],
            "intent_context": case["intent_context"],
        },
        "chosen": chosen,
        "rejected": _rejected_output(chosen, mode, case),
        "preference_reason": [
            "chosen output preserves the expected policy decision, risk IDs, severity, controls, and safe response",
            f"rejected output demonstrates {mode.replace('_', ' ')} for preference training",
        ],
    }


def build_sft_records() -> list[dict]:
    records: list[dict] = []
    for case in P0_CASES:
        for suffix, prompt_template in VARIANT_SUFFIXES:
            records.append(_phase15_sft_record(_variant_case(case, suffix, prompt_template), suffix))
    return records


def build_dpo_records() -> list[dict]:
    records: list[dict] = []
    for case in P0_CASES:
        modes = ["unsafe_allow", "missing_audit"]
        if case["category"] == "benign":
            modes = ["over_refusal", "missing_audit"]
        for index, mode in enumerate(modes, start=1):
            records.append(_dpo_pair(case, index, mode))
    return records


def _manifest(sft_records: list[dict], dpo_records: list[dict]) -> dict:
    category_counts = Counter(record["labels"]["primary_category"] for record in sft_records)
    decision_counts = Counter(record["labels"]["decision"] for record in sft_records)
    dpo_modes = Counter(
        record["rejected"]["evidence"][0]["value"].split(" candidate for ", maxsplit=1)[0]
        for record in dpo_records
    )
    return {
        "version": "1.5.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "source": "scripts/generate_phase15_assets.py",
        "inputs": {
            "p0_seed_cases": len(P0_CASES),
            "variant_templates_per_case": len(VARIANT_SUFFIXES),
        },
        "outputs": {
            "sft_records": len(sft_records),
            "dpo_preference_pairs": len(dpo_records),
            "sft_path": "training/phase15-sft-bootstrap.jsonl",
            "dpo_path": "training/phase15-dpo-preference-bootstrap.jsonl",
        },
        "coverage": {
            "primary_category_counts": dict(sorted(category_counts.items())),
            "decision_counts": dict(sorted(decision_counts.items())),
            "dpo_pair_count": len(dpo_records),
            "dpo_rejected_modes": dict(sorted(dpo_modes.items())),
        },
        "quality_notes": [
            "Deterministic expansion only; all Phase 1.5 records remain pending human review.",
            "SFT variants preserve labels while rewriting prompt wrappers and context framing.",
            "DPO rejected outputs are schema-valid but intentionally policy-inferior.",
        ],
    }


def main() -> None:
    sft_records = build_sft_records()
    dpo_records = build_dpo_records()

    write_jsonl(TRAINING / "phase15-sft-bootstrap.jsonl", sft_records)
    write_jsonl(TRAINING / "phase15-dpo-preference-bootstrap.jsonl", dpo_records)

    manifest = _manifest(sft_records, dpo_records)
    EVALUATION.mkdir(parents=True, exist_ok=True)
    (EVALUATION / "phase15-dataset-manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Generated {len(sft_records)} Phase 1.5 SFT records")
    print(f"Generated {len(dpo_records)} Phase 1.5 DPO preference pairs")
    print(f"Manifest: {EVALUATION / 'phase15-dataset-manifest.json'}")


if __name__ == "__main__":
    main()
