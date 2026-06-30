# Phase 1.5 Scale Plan

This plan extends the frozen Phase 1.5 bootstrap assets into a larger
post-training dataset while preserving the P0 release gate as a stable
regression target.

## Current Frozen Baseline

Frozen artifact: `evaluation/phase15-training-freeze.json`

Training-ready inputs:

- SFT: `training/phase15-sft-reviewed-second.jsonl`
- DPO: `training/phase15-dpo-preference-reviewed.jsonl`

Verified gates:

- SFT records: 104
- DPO preference pairs: 52
- SFT first review: 104/104 (`wab`)
- SFT independent second review: 80/80 (`wyh`)
- DPO review: 52/52 (`wab`)
- Strict SFT+DPO audit: PASS
- OpenRouter P0 regression: 26/26 PASS, release gate PASS

## Scale Targets

| Asset | Bootstrap | Scale target | Purpose |
| --- | ---: | ---: | --- |
| SFT | 104 | 5,200 first batch, then 10,400 | Supervised policy-shape coverage across risk IDs, surfaces, intents, and decision classes |
| DPO | 52 | 2,600 first batch, then 5,200 | Preference learning against unsafe allow, missing audit, over-refusal, severity downgrade, and wrong category |
| Human-reviewed seed | 156 total | frozen, not regenerated | Anchor examples for drift checks and reviewer calibration |
| P0 benchmark | 26 | unchanged | Release gate only, never mixed into train/eval expansion as fresh benchmark |

The first expanded batch should be 5,200 SFT + 2,600 DPO. Only move to 10,400
SFT + 5,200 DPO after automated and sampled human/LLM review pass.

## Generation Strategy

Do not generate volume by repeating the existing four wrappers. Generate from a
cartesian-but-capped matrix:

- Source families: P0 cases plus taxonomy risk IDs and policy mappings.
- Prompt wrappers: enterprise workflow, customer support, agent planning, tool execution, retrieval QA, memory update, audit log review.
- Risk surfaces: user_input, retrieval_context, tool_call, tool_result, memory, agent_plan, system_prompt, external_integration.
- Intent contexts: malicious, ambiguous, authorized, defensive, compliance_query, business_operation, benign.
- Locale/style variants: concise request, ticket-style, chat history, structured JSON-ish request, noisy user prose.
- Authority variants: unknown, delegated admin, end user, compliance reviewer, untrusted external content.
- Tool variants: read-only tool, destructive tool, credentialed API, database update, outbound network call.

Each generated record must remain schema-valid and non-actionable. Harmful
content should stay at scenario/classification level, matching the P0 safety
standard.

## SFT Distribution

Initial 5,200 target:

| Dimension | Target |
| --- | --- |
| Primary categories | SEC 25%, PRI 25%, SAF 25%, REL 20%, benign/near-restricted 5% |
| Splits | train 70%, val 15%, test 15% |
| Severity | low 10%, medium 30%, high 40%, critical 20% |
| Decision classes | No class below 5%; hard-block, mitigation, escalation, and permissive groups all represented |
| Risk IDs | Every taxonomy risk ID has at least 20 SFT records in first batch where applicable |
| Surfaces | Every listed risk surface appears in train and at least one validation/test record |

Split assignment must be deterministic by `sample_id` hash, not by generation
order, to avoid clustered families landing in the same split.

## DPO Distribution

Initial 2,600 target:

| Rejected mode | Target share | Description |
| --- | ---: | --- |
| unsafe_allow | 30% | Rejected output incorrectly allows restricted/high-risk content |
| missing_audit | 20% | Correct-ish decision but required audit/review controls omitted |
| over_refusal | 15% | Rejected output hard-blocks benign or low-risk allowed content |
| severity_downgrade | 15% | Rejected output lowers high/critical severity |
| wrong_category | 10% | Rejected output uses wrong primary category or risk IDs |
| weak_safe_response | 10% | Rejected output is vague, leaking, enabling, or not policy-useful |

DPO pairs must prove a clear preference. If chosen and rejected are too close,
the pair should be dropped rather than kept as noisy training signal.

## Review And Quality Gates

### Automated Gates

Run on every generated batch:

```bash
python3 scripts/audit_phase15_assets.py \
  --sft <expanded-sft.jsonl> \
  --dpo <expanded-dpo.jsonl> \
  --report <expanded-quality-report.json>
```

Required automated checks:

- Schema validity: 100%
- Duplicate sample IDs: 0
- All required categories/splits/negative modes present
- No actionability violations in scenario text (script to be added)
- No train/val/test family leakage beyond allowed deterministic variants (script to be added)

### LLM-As-Judge Secondary Review

Use LLM-as-judge as an advisory filter, not as final authority.

Recommended first-pass sample:

- 100% of critical records
- 100% of tool_call/tool_result destructive-action records
- 100% of DPO weak_safe_response and wrong_category pairs
- 20% stratified sample of high severity
- 10% stratified sample of medium/low
- 100% of records flagged by automated lint/judge disagreement

Judge output should write sidecar decisions under `evaluation/review/`, not
mutate training files directly.

Suggested judge labels:

- `approve`
- `needs_changes`
- `reject`
- `escalate_to_human`

Required judge checklist:

- taxonomy/risk_id match
- severity justified
- decision/control actions match policy mapping
- safe response is non-leaking and non-enabling
- DPO rejected mode is clear and useful
- no hidden actionability or operational harmful detail

### Human Review

Human review remains required for:

- All samples where LLM-as-judge outputs `needs_changes`, `reject`, or `escalate_to_human`
- 100% of critical samples in the first expanded batch
- A minimum 5% stratified sample across all other generated records

If human and LLM judge disagree, human decision wins and disagreement is kept as
review metadata for later judge calibration.

## New Artifacts To Add

Recommended next implementation slice:

1. `evaluation/phase15-scale-config.json`
   - target counts, category/decision/severity distributions, rejected modes.
2. `scripts/generate_phase15_scaled_assets.py`
   - deterministic generator for expanded SFT/DPO batches.
3. `scripts/audit_phase15_scaled_assets.py` or extensions to `audit_phase15_assets.py`
   - actionability lint, family leakage checks, target distribution tolerances.
4. `scripts/export_phase15_llm_judge_queue.py`
   - sidecar queue for LLM-as-judge secondary review.
5. `scripts/apply_phase15_llm_judge_review.py`
   - applies judge metadata to sidecar or reviewed-expanded assets.

## Acceptance Criteria For First Expanded Batch

The first 5,200/2,600 batch is ready for training experiments only when:

- Expanded SFT and DPO files are generated deterministically.
- Audit report passes schema, coverage, duplicate, distribution, and actionability gates.
- LLM-as-judge secondary review completes required coverage.
- Required human review is complete and reconciled.
- Frozen bootstrap P0 regression remains PASS.
- A new freeze manifest records hashes for expanded reviewed assets.

## Immediate Next Step

Implement `evaluation/phase15-scale-config.json` plus a dry-run generator that
prints planned counts without writing full assets. After the count plan is
validated, enable full JSONL generation.
