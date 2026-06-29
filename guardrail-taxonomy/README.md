# Guardrail Taxonomy — Phase 1 交付物

面向 **Guardrail LLM / Enterprise AI Security Control Plane** 的可执行数据底座，与以下设计文档对齐：

- `[0-2]Phase1-Guardrail LLM Risk Taxonomy v1.0.md`
- `[0-3]Phase1-Policy-to-Decision Mapping v1.0.md`
- `[0-3]Phase1-Guardrail-Schema-v1.0.md`

## 目录结构

```text
guardrail-taxonomy/
├── schemas/           # JSON Schema（运行时决策、训练数据、Golden Test）
├── taxonomy/          # 风险本体与策略映射（YAML）
├── lint/              # Policy Lint 规则与配置
├── benchmarks/        # P0 自动化评测种子集（JSONL）
├── golden/            # 确定性回归测试用例（YAML）
├── training/          # SFT 引导训练样本（JSONL）
└── scripts/           # 资产生成脚本
```

## Phase 1 五项交付物

| # | 交付物 | 路径 |
|---|--------|------|
| 1 | Guardrail Decision JSON Schema | `schemas/guardrail-decision.schema.json` |
| 2 | Training Data JSONL Format | `schemas/training-record.schema.json` + `training/sft-seed-bootstrap.jsonl` |
| 3 | Golden Test Case Template | `schemas/golden-test.schema.json` + `golden/*.yaml` |
| 4 | Policy Lint Rules | `lint/policy-lint-rules.v1.yaml` + `lint/lint-config.yaml` |
| 5 | P0 Benchmark Seed Set | `benchmarks/p0-seed-set.jsonl` (+ 分类子集) |

## 支撑文档（机器可读）

| 文档 | 路径 |
|------|------|
| Risk Taxonomy v1.0 | `taxonomy/risk-taxonomy.v1.yaml` |
| Policy-to-Decision Mapping v1.0 | `taxonomy/policy-to-decision-mapping.v1.yaml` |

## 快速使用

### 重新生成 P0 与 SFT 种子数据

```bash
python3 scripts/generate_phase1_assets.py
```

### P0 评测集统计

- 合计 **26** 条 P0 seed cases（SEC 5 + PRI 5 + SAF 6 + REL 5 + Benign 5）
- 覆盖 SEC / PRI / SAF / REL 四大类及 benign / near-restricted 场景
- 所有样本均为非行动化、可自动评估的安全占位描述

### Golden Tests

每个主风险类至少 1 条确定性 golden test：

- `golden/golden-sec.yaml` — 越狱拒绝
- `golden/golden-pri.yaml` — 凭证泄露阻断
- `golden/golden-saf.yaml` — 网络滥用拒绝
- `golden/golden-rel.yaml` — 伪造引用转换
- `golden/golden-benign.yaml` — 良性请求放行（过拒防护）

## Phase 1 完成标准

```yaml
# 见 phase1-completion-criteria.yaml
taxonomy: 全部 risk ID 有稳定名称、默认严重度与控制映射
schema: 决策 schema 可校验运行时输出；训练格式支持 SFT/DPO/KTO/RLVR
golden_tests: 每主类至少 1 条确定性 golden test
lint: 规则覆盖 unsafe allow、缺失脱敏、缺失审计、非法枚举
p0_benchmark: 覆盖 SEC/PRI/SAF/REL/benign；无行动化有害细节
release_gate_ready: P0 可在发布前自动运行；critical unsafe allow 为硬阻断
```

## 下一步（Phase 1.5 / Phase 2 前置）

1. 扩展至 100+ 人工审核 SFT/DPO bootstrap 样本
2. 实现 P0 runner scoring rubric 与 rule-based judge
3. 接入 CI/CD release gate 流水线
4. 按 taxonomy 覆盖率扩展至 5K–10K 高质量训练样本
