"""Guardrail decision schema validation backed by jsonschema (Draft 2020-12)."""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import List

from jsonschema import Draft202012Validator

from . import ROOT

DECISION_SCHEMA_PATH = ROOT / "schemas" / "guardrail-decision.schema.json"


@functools.lru_cache(maxsize=4)
def _validator(schema_path: str) -> Draft202012Validator:
    with Path(schema_path).open(encoding="utf-8") as handle:
        schema = json.load(handle)
    return Draft202012Validator(schema)


def validate_decision(decision: dict, schema_path: Path = DECISION_SCHEMA_PATH) -> List[str]:
    """Return a list of human-readable schema errors (empty list means valid)."""
    validator = _validator(str(schema_path))
    errors = sorted(validator.iter_errors(decision), key=lambda e: list(e.path))
    messages: List[str] = []
    for err in errors:
        location = "/".join(str(p) for p in err.path) or "<root>"
        messages.append(f"{location}: {err.message}")
    return messages
