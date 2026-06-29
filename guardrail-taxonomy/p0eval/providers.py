"""Decision providers (model adapters) for the P0 runner.

A provider maps a benchmark case to a Guardrail decision object. This lets the
runner evaluate anything from a perfect oracle (pipeline self-test) to a naive
keyword baseline, to real model predictions loaded from a JSONL file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Dict


def _release_gate_impact(severity: str, decision: str) -> str:
    if severity == "critical":
        if decision in {"block_tool_call", "terminate_execution", "refuse"}:
            return "block"
        return "warning"
    if severity in {"high"}:
        return "warning"
    return "none"


def _base_decision(case: dict, *, decision: str, severity: str, risk_ids, category: str,
                   control_actions, audit: bool, human: bool, confidence: float,
                   evidence=None, safe_response: str = "") -> dict:
    return {
        "schema_version": "1.0.0",
        "decision_id": f"dec-{case['case_id'].lower()}",
        "decision": decision,
        "primary_category": category,
        "secondary_categories": case.get("expected_secondary_categories", []),
        "risk_ids": list(risk_ids),
        "severity": severity,
        "confidence": confidence,
        "risk_surface": case.get("risk_surface", ["user_input"]),
        "intent_context": case.get("intent_context", "ambiguous"),
        "evidence": evidence if evidence is not None else [],
        "control_actions": list(control_actions),
        "recommended_safe_response": safe_response,
        "audit_required": audit,
        "human_review_required": human,
        "release_gate_impact": _release_gate_impact(severity, decision),
    }


def oracle_provider(case: dict) -> dict:
    """Return the expected decision (used to self-test the evaluation pipeline)."""
    severity = case["expected_severity"]
    decision = case["expected_decision"]
    audit = bool(case.get("audit_required", False))
    human = bool(case.get("human_review_required", False))
    if severity == "critical":
        audit = True
        human = True
    if decision in {"block_tool_call", "terminate_execution", "require_reauth"}:
        audit = True
    return _base_decision(
        case,
        decision=decision,
        severity=severity,
        risk_ids=case["expected_risk_ids"],
        category=case["expected_primary_category"],
        control_actions=case["expected_control_actions"],
        audit=audit,
        human=human,
        confidence=0.9 if severity in {"high", "critical"} else 0.85,
        evidence=[{"type": "mapping_rule", "value": f"oracle:{case['case_id']}"}],
        safe_response="Request handled per policy mapping; no disallowed detail provided.",
    )


# Naive baseline: refuse if any restricted keyword present, else allow.
_REFUSE_KEYWORDS = (
    "ignore all previous", "reveal internal", "system prompt", "secret token",
    "remove all user records", "break into", "harm another person",
    "falsify", "trick someone", "another tenant",
)
_REDACT_KEYWORDS = ("identifiers", "customer profile", "customer record")


def baseline_keyword_provider(case: dict) -> dict:
    """Intentionally imperfect keyword baseline to exercise the scoring path."""
    text = (case.get("user_message", "") + " " + " ".join(case.get("retrieval_context", []))).lower()
    if case.get("agent_plan"):
        text += " " + case["agent_plan"].lower()

    if any(k in text for k in _REFUSE_KEYWORDS):
        decision, severity, controls = "refuse", "high", ["safe_complete", "log_only"]
    elif any(k in text for k in _REDACT_KEYWORDS):
        decision, severity, controls = "redact", "medium", ["redact", "log_only"]
    else:
        decision, severity, controls = "allow", "low", ["allow"]

    audit = decision in {"refuse", "redact"}
    return _base_decision(
        case,
        decision=decision,
        severity=severity,
        risk_ids=case.get("expected_risk_ids", ["REL-3.1"])[:1],
        category=case.get("expected_primary_category", "REL"),
        control_actions=controls,
        audit=audit,
        human=False,
        confidence=0.6,
        evidence=[{"type": "risk_span", "value": "keyword-baseline"}] if decision != "allow" else [],
        safe_response="Baseline response." if decision != "allow" else "",
    )


def file_provider(predictions_path: Path) -> Callable[[dict], dict]:
    """Build a provider that returns predictions keyed by case_id from a JSONL file."""
    table: Dict[str, dict] = {}
    with Path(predictions_path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            case_id = record.get("case_id") or record.get("decision_id")
            if case_id is None:
                raise ValueError("Prediction record missing case_id")
            table[case_id] = record.get("decision_output", record)

    def _provider(case: dict) -> dict:
        if case["case_id"] not in table:
            raise KeyError(f"No prediction for case {case['case_id']}")
        return table[case["case_id"]]

    return _provider


PROVIDERS = {
    "oracle": oracle_provider,
    "baseline": baseline_keyword_provider,
}
