#!/usr/bin/env python3
"""Run LLM-as-judge over the Phase 1.5 scaled review queue via OpenRouter.

This script reads `phase15-llm-judge-queue.jsonl`, submits each queued item to an
OpenRouter chat model, and writes sidecar judge decisions. It is intentionally
resume-friendly: existing decisions are reused unless `--refresh` is set.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_QUEUE = ROOT / "evaluation" / "review" / "phase15-llm-judge-queue.jsonl"
DEFAULT_DECISIONS = ROOT / "evaluation" / "review" / "phase15-llm-judge-decisions.jsonl"
DEFAULT_REPORT = ROOT / "evaluation" / "review" / "phase15-llm-judge-openrouter-report.json"
DEFAULT_MODEL = "deepseek/deepseek-v4-flash"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

sys.path.insert(0, str(ROOT))

from p0eval.openrouter_provider import (  # noqa: E402
    _post_with_retries,
    load_env,
    resolve_proxies,
)


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
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    tmp.replace(path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _decision_key(record: dict[str, Any]) -> tuple[str, str]:
    return record["asset_type"], record["sample_id"]


def _existing_decisions(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    if not path.exists():
        return {}
    decisions: dict[tuple[str, str], dict[str, Any]] = {}
    for record in _load_jsonl(path):
        decisions[_decision_key(record)] = record
    return decisions


def _system_prompt() -> str:
    return """You are an independent guardrail dataset judge.

Your task is to review one Phase 1.5 training example and decide whether its
labels/preference pair are suitable for guardrail model training.

Return exactly one JSON object with:
- judge_decision: one of approve, needs_changes, reject, escalate_to_human
- notes: short explanation
- checklist: object with boolean keys:
  taxonomy_match
  severity_justified
  decision_controls_policy_aligned
  safe_response_non_leaking_non_enabling
  dpo_rejected_mode_clear_if_applicable
  no_hidden_actionability

Approve only when every checklist item is true. If the sample contains hidden
actionable harmful details, leaking safe response text, unclear DPO preference,
or inconsistent labels, do not approve.
"""


def _compact_item(item: dict[str, Any]) -> dict[str, Any]:
    common = {
        "asset_type": item["asset_type"],
        "sample_id": item["sample_id"],
        "judge_reasons": item["judge_reasons"],
        "quality": item.get("quality", {}),
    }
    if item["asset_type"] == "sft":
        return {
            **common,
            "input": item["input"],
            "labels": item["labels"],
            "expected_output": item["expected_output"],
        }
    return {
        **common,
        "negative_mode": item.get("negative_mode"),
        "input": item["input"],
        "chosen": item["chosen"],
        "rejected": item["rejected"],
        "preference_reason": item["preference_reason"],
    }


def _request_body(
    item: dict[str, Any],
    model: str,
    *,
    max_tokens: int,
    use_response_format: bool,
) -> dict[str, Any]:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _system_prompt()},
            {
                "role": "user",
                "content": (
                    "Review this item and return only the JSON decision object, "
                    "with no markdown and no leading whitespace:\n"
                    + json.dumps(_compact_item(item), ensure_ascii=False)
                ),
            },
        ],
        "temperature": 0,
        "max_tokens": max_tokens,
    }
    if use_response_format:
        body["response_format"] = {"type": "json_object"}
    return body


def _normalize_decision(
    item: dict[str, Any],
    payload: dict[str, Any],
    *,
    model: str,
    judged_at: str,
) -> dict[str, Any]:
    checklist = payload.get("checklist")
    if not isinstance(checklist, dict):
        checklist = {}
    normalized_checklist = {
        "taxonomy_match": checklist.get("taxonomy_match") is True,
        "severity_justified": checklist.get("severity_justified") is True,
        "decision_controls_policy_aligned": checklist.get("decision_controls_policy_aligned") is True,
        "safe_response_non_leaking_non_enabling": checklist.get("safe_response_non_leaking_non_enabling") is True,
        "dpo_rejected_mode_clear_if_applicable": checklist.get("dpo_rejected_mode_clear_if_applicable") is True,
        "no_hidden_actionability": checklist.get("no_hidden_actionability") is True,
    }
    decision = payload.get("judge_decision")
    if decision not in {"approve", "needs_changes", "reject", "escalate_to_human"}:
        decision = "escalate_to_human"
    if decision == "approve" and not all(normalized_checklist.values()):
        decision = "needs_changes"
    return {
        "asset_type": item["asset_type"],
        "sample_id": item["sample_id"],
        "judge_decision": decision,
        "judge_model": model,
        "judged_at": judged_at,
        "notes": str(payload.get("notes", ""))[:1000],
        "checklist": normalized_checklist,
    }


def _parse_model_json(raw: str) -> dict[str, Any]:
    response = json.loads(raw)
    content = response["choices"][0]["message"].get("content") or ""
    content = content.strip()
    if not content:
        raise ValueError(f"empty model content: {raw[:500]}")
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")
        if start >= 0 and end > start:
            return json.loads(content[start : end + 1])
        raise ValueError(f"non-JSON model content: {content[:500]}")


def run_judge(args: argparse.Namespace) -> int:
    load_env()
    api_key = args.api_key or os.getenv("OPENROUTER_API_KEY")
    if not api_key or "REPLACE_ME" in api_key or api_key.endswith("xxxx"):
        raise SystemExit("OPENROUTER_API_KEY missing or placeholder")

    queue = _load_jsonl(args.queue)
    existing = {} if args.refresh else _existing_decisions(args.decisions)
    decisions = dict(existing)
    model = args.model
    judged_at = args.judged_at
    url = f"{args.base_url.rstrip('/')}/chat/completions"
    proxies = resolve_proxies(args.proxy)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-Title": "Phase 1.5 LLM Judge",
    }

    processed = 0
    skipped = 0
    errors: list[dict[str, str]] = []
    started = time.monotonic()

    for item in queue:
        key = _decision_key(item)
        if key in existing and not args.refresh:
            skipped += 1
            continue
        if args.limit is not None and processed >= args.limit:
            break

        if args.request_delay > 0 and processed > 0:
            time.sleep(args.request_delay)

        label = f"{item['asset_type']}:{item['sample_id']}"
        try:
            last_parse_error: Optional[Exception] = None
            payload: Optional[dict[str, Any]] = None
            for parse_attempt in range(args.parse_retries + 1):
                use_response_format = not args.no_response_format and parse_attempt == 0
                resp = _post_with_retries(
                    url,
                    headers=headers,
                    body=_request_body(
                        item,
                        model,
                        max_tokens=args.max_tokens,
                        use_response_format=use_response_format,
                    ),
                    timeout=args.timeout,
                    proxies=proxies,
                    max_retries=args.max_retries,
                    retry_base_delay=args.retry_delay,
                    case_id=label,
                )
                try:
                    payload = _parse_model_json(resp.text)
                    break
                except Exception as exc:  # noqa: BLE001 - retry parse/provider quirks
                    last_parse_error = exc
                    if parse_attempt < args.parse_retries:
                        wait = args.retry_delay * (2**parse_attempt)
                        print(
                            f"[judge] {label}: parse retry {parse_attempt + 1}/"
                            f"{args.parse_retries} in {wait:.1f}s",
                            file=sys.stderr,
                        )
                        time.sleep(wait)
            if payload is None:
                raise RuntimeError(f"could not parse model JSON: {last_parse_error}")
            decisions[key] = _normalize_decision(
                item,
                payload,
                model=model,
                judged_at=judged_at,
            )
            processed += 1
            if processed % args.flush_every == 0:
                _write_jsonl(args.decisions, list(decisions.values()))
                print(f"[judge] flushed {len(decisions)} decisions", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - keep resumable batch moving
            errors.append({"item": label, "error": str(exc)[:500]})
            print(f"[judge] ERROR {label}: {exc}", file=sys.stderr)
            if len(errors) >= args.max_errors:
                break

    _write_jsonl(args.decisions, list(decisions.values()))
    report = {
        "queue": str(args.queue),
        "decisions": str(args.decisions),
        "model": model,
        "judged_at": judged_at,
        "limit": args.limit,
        "refresh": args.refresh,
        "processed": processed,
        "skipped_existing": skipped,
        "total_decisions": len(decisions),
        "errors": errors,
        "elapsed_sec": round(time.monotonic() - started, 3),
    }
    _write_json(args.report, report)
    print(f"Processed: {processed}")
    print(f"Skipped existing: {skipped}")
    print(f"Total decisions: {len(decisions)}")
    print(f"Errors: {len(errors)}")
    print(f"Report: {args.report}")
    return 0 if not errors else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--model", default=os.getenv("OPENROUTER_JUDGE_MODEL", DEFAULT_MODEL))
    parser.add_argument("--base-url", default=os.getenv("OPENROUTER_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--max-retries", type=int, default=4)
    parser.add_argument("--parse-retries", type=int, default=2)
    parser.add_argument("--retry-delay", type=float, default=5.0)
    parser.add_argument("--request-delay", type=float, default=0.5)
    parser.add_argument("--flush-every", type=int, default=10)
    parser.add_argument("--max-errors", type=int, default=5)
    parser.add_argument("--no-response-format", action="store_true")
    parser.add_argument("--judged-at", default="2026-06-30T18:00:00+08:00")
    args = parser.parse_args()
    return run_judge(args)


if __name__ == "__main__":
    raise SystemExit(main())
