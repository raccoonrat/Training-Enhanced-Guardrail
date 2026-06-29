下面是对当前 **Shared Taxonomy (NEW)** 的批判性审阅。我会从 **AI 安全科学性、训练增强 Guardrail LLM 可用性、工程落地、评测闭环、企业控制平面适配性** 五个角度看。整体判断：**这版 taxonomy 已具备较好的一级框架雏形，但仍更像“风险清单”，还没有完全达到“可训练、可评测、可治理、可执行”的 Guardrail LLM taxonomy 标准。**

***

# 1. 总体评价

当前 taxonomy 将风险分为四大类：**Security、Privacy、Safety、Reliability**，并分别定义为 AI 在对抗条件下保持未被攻破、敏感数据被保护、系统不促成伤害/违法/歧视、输出可靠谨慎稳定。这个一级分类方向是合理的，覆盖了 Guardrail LLM 最核心的四类目标。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

但从训练增强 Guardrail LLM 的路线图来看，它还存在一个根本问题：

> **当前 taxonomy 更适合“人工阅读和标注参考”，但还不够适合作为模型训练、自动评测、策略执行和 release gate 的统一本体。**

主要原因有四点：

1. **分类边界仍有重叠**：例如 policy compliance、tool-use policy violation、unauthorized action execution、goal hijacking 都可能同时属于 Security/Agent Safety/Policy Violation。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)
2. **输入风险、输出风险、行为风险混在一起**：文档同时讨论 restricted input、restricted output、多风险输入/输出，以及 agent action，但没有明确区分检测对象。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)
3. **taxonomy 与 control action 尚未绑定**：目前有风险类别，但没有系统定义 allow / deny / redact / escalate / constrain / log / human-review 等控制动作。
4. **Reliability 明显过窄**：当前 Reliability 只有 hallucination & misinformation，并包含 factual errors、safe deferral failing 两个 threat，无法覆盖企业级 AI 系统中稳定性、一致性、置信度校准、引用错误、工具结果误读、长上下文漂移等问题。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

***

# 2. 主要优点

## 2.1 一级分类方向是对的

四大类 Security / Privacy / Safety / Reliability 是一个清晰、可沟通的上层结构。它符合企业 AI 安全中常见的四条主线：

* **Security**：模型、Agent、工具链是否被攻击或越权；
* **Privacy**：个人数据、凭证、商业秘密、系统内部信息是否泄露；
* **Safety**：输出或行为是否造成现实伤害、非法行为、歧视或伦理风险；
* **Reliability**：输出是否真实、稳定、谨慎、可依赖。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这对 leadership 对齐非常有价值，因为四个词都足够高层，也足以映射到产品风险。

## 2.2 Security 部分已经体现 Agent 化风险

Security 下不仅有 policy compliance、access & action control、availability，还进一步拆出了 jailbreak、tool-use policy violation、goal hijacking、unauthorized access、unauthorized action execution、context & memory integrity abuse、runaway execution、resource exhaustion、DoS/wallet 等 threat。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这是一个亮点。它说明 taxonomy 已经从传统内容安全，推进到 **Agent runtime security**：

```text
Prompt attack
→ Tool-use violation
→ Goal hijacking
→ Unauthorized action
→ Memory/context poisoning
→ Resource exhaustion
```

这非常适合你们 Enterprise AI Security Control Plane / Guardrail LLM 的方向。

## 2.3 Privacy 部分覆盖较完整

Privacy 下包括 PII disclosure、secrets/credentials disclosure、privacy violation、confidential business data leakage、IP infringement、system prompt / hidden instruction disclosure、model extraction、unnecessary sensitive data sent to models/tools。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这很重要，因为很多 taxonomy 只关注 PII，而当前版本已经把：

* 个人数据；
* 凭证密钥；
* 商业机密；
* 系统提示；
* 模型抽取；
* 不必要数据传输；

纳入 Privacy/Information Protection 范围。这个方向适合企业级安全治理。

## 2.4 Safety 部分覆盖较广

Safety 下有 harm、bias、content safety、business ethics 四个 subcategory，同时 threat 层覆盖 self-harm assistance、violence/criminal wrongdoing enablement、cybercrime/malware enablement、fraud/social engineering enablement、hate/extremism/harassment、personal safety and rights harm、manipulative persuasion，以及 bias 和 business ethics 的多个细分项。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这里的优点是：它没有把 Safety 简化为“有害内容”，而是包括了：

* 现实伤害；
* 欺诈和社会工程；
* 偏见和公平性；
* 商业伦理；
* 受监管/敏感内容风险。

这对面向企业客户的 AI guardrail 很有价值。

***

# 3. 核心问题与批判性意见

## 3.1 问题一：一级分类之间存在概念重叠

最明显的是 **Security vs Safety vs Business Ethics vs Reliability** 的边界不够稳定。

例如：

* “Cybercrime / malware enablement” 当前放在 Safety → Harm 下。  
  但从 AI 安全控制平面角度，它也强烈属于 Security，因为它涉及攻击能力增强、工具滥用和系统入侵。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)
* “Tool-use Policy Violation” 在 Security → Policy Compliance 下。  
  但如果工具调用造成现实损害，它也属于 Safety。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)
* “Business ethics violation” 放在 Safety → Business Ethics 下。  
  但其中部分 deception/fraud/manipulation 与 Safety → Harm 下的 fraud/social engineering enablement 高度重叠。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf) [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)
* “Safe deferral failing” 放在 Reliability 下。  
  但在很多场景中，safe deferral failing 更像 Safety 或 Policy Compliance 问题，而不仅是可靠性问题。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

### 建议

引入 **primary category + secondary flags** 机制：

```yaml
primary_category: SEC
secondary_categories:
  - SAF
  - PRI
```

例如：

```yaml
risk_id: CYBER-ENABLEMENT
primary_category: SEC
secondary_categories: [SAF]
reason: Enables cyber abuse and may cause real-world harm.
```

这样可以避免强行单归类带来的争议。

***

## 3.2 问题二：“输入/输出/行为/状态”没有分层

当前文档区分了 Restricted Input Example 和 Restricted Output Example，并说明测试用例可能同时标记 security、privacy、safety 等多个风险。 但对 Guardrail LLM 来说，检测对象至少有四类： [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```text
1. User Input Risk
2. Model Output Risk
3. Agent Action Risk
4. System State / Memory / Context Risk
```

现在 taxonomy 把它们混在风险类别中，导致训练样本会出现歧义。

例如：

* “Ignore previous instructions...” 是输入攻击；
* “Here are the available tools...” 是输出泄露；
* “I deleted all rows...” 是行为执行结果；
* “trusted sources are poisoned...” 是上下文/记忆完整性问题。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这些不应只靠 category/subcategory 区分，而应在 schema 中明确标注：

```yaml
risk_surface:
  - input
  - output
  - tool_call
  - memory
  - retrieval_context
  - system_state
  - log
```

### 建议

为每个 threat 增加 `risk_surface` 字段。示例：

```yaml
threat: Goal Hijacking
category: SEC
subcategory: SEC-1 Policy Compliance
risk_surface:
  - input
  - retrieval_context
  - memory
  - agent_plan
control_points:
  - pre_prompt_guard
  - retrieval_filter
  - plan_validator
  - runtime_monitor
```

这会让 taxonomy 直接服务 Guardrail LLM 训练和 runtime control plane。

***

## 3.3 问题三：缺少“控制动作空间”

当前 taxonomy 定义的是风险类别和风险说明，但没有定义每类风险触发后应该如何处理。对于 Guardrail LLM，这是致命缺口。

Guardrail 的最终输出不应只是：

```json
{
  "risk_category": "SEC-2"
}
```

而应是：

```json
{
  "decision": "deny",
  "risk_category": "SEC-2",
  "severity": "high",
  "control_action": "block_tool_call",
  "audit_required": true
}
```

### 建议增加 Control Action Taxonomy

建议定义如下控制动作：

```yaml
control_actions:
  allow:
    description: Request is safe and should proceed.
  allow_with_constraints:
    description: Proceed only with limited scope, sandbox, or reduced privileges.
  refuse:
    description: Do not answer or execute.
  safe_complete:
    description: Provide safe alternative information.
  redact:
    description: Remove or mask sensitive data.
  transform:
    description: Rewrite into safe form.
  escalate:
    description: Require human review or approval.
  block_tool_call:
    description: Prevent tool/API/action execution.
  require_reauth:
    description: Require stronger identity or permission check.
  log_only:
    description: Allow but record for audit.
  rate_limit:
    description: Throttle repetitive or costly behavior.
```

这会让 taxonomy 从“分类体系”升级为“policy execution ontology”。

***

## 3.4 问题四：Security 的 SEC-1 过于宽泛

SEC-1 Policy Compliance 当前定义为产品遵守 intended behavior、policies、constraints 和 operational boundaries。风险是产品违反 intended policies、constraints 或 operational objectives。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这个定义太大，几乎所有安全问题都可以归到 SEC-1。它容易成为“垃圾桶类别”。

例如：

* jailbreak 是 policy compliance；
* tool-use policy violation 也是 policy compliance；
* goal hijacking 也是 policy compliance；
* risky outputs 也是 policy compliance。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

### 建议

将 SEC-1 拆为两个更清晰的子类：

```text
SEC-1 Instruction & Policy Integrity
- Jailbreak
- System instruction override
- Goal hijacking
- Prompt hierarchy violation

SEC-2 Runtime Permission & Action Control
- Unauthorized access
- Unauthorized action
- Tool-use policy violation
- Approval bypass

SEC-3 Context, Memory & Retrieval Integrity
- Memory poisoning
- Context injection
- Trusted source abuse
- RAG instruction contamination

SEC-4 Availability & Cost Abuse
- Runaway execution
- Resource exhaustion
- DoS/wallet drain
```

这样比当前 SEC-1/SEC-2/SEC-3 更适合 Agentic AI。

***

## 3.5 问题五：Privacy 中 System Prompt Disclosure 放置有争议

当前 taxonomy 将 “System prompt / hidden instruction disclosure” 放在 Privacy → IP 下，定义为暴露 system prompts、hidden policies、tool schemas、internal constraints。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这有一定合理性，因为系统提示和工具 schema 可能是内部资产。但从安全架构视角，它同时也是 **Security / Policy Integrity** 问题：

* 泄露 system prompt 会降低 jailbreak 成功成本；
* 泄露 tool schemas 会帮助攻击者构造工具调用攻击；
* 泄露 internal constraints 会帮助规避 guardrail。

### 建议

保留在 Privacy/IP 下，但增加 secondary flag：

```yaml
threat: System Prompt / Hidden Instruction Disclosure
primary_category: PRI
secondary_categories: [SEC]
risk_surface:
  - output
  - tool_schema
  - debug_trace
control_actions:
  - refuse
  - redact
  - safe_complete
  - log
```

***

## 3.6 问题六：Reliability 维度严重不足

当前 Reliability 只有 REL-1 Hallucinations & Misinformation，下面只有 factual errors / misinformation 和 safe deferral failing。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这对 Guardrail LLM 和企业 AI 系统远远不够。Reliability 应至少覆盖：

1. **Grounding failure**：回答未基于证据；
2. **Citation fabrication**：伪造引用；
3. **Confidence miscalibration**：过度自信；
4. **Instruction inconsistency**：同类问题回答不一致；
5. **Long-context instability**：长上下文中前后矛盾；
6. **Tool result misinterpretation**：错误解读工具返回；
7. **Unsafe uncertainty handling**：不确定时没有降级或转人工；
8. **Regression instability**：版本更新后安全能力下降。

### 建议 REL 重构

```text
REL-1 Factuality & Grounding
REL-2 Uncertainty & Deferral
REL-3 Consistency & Stability
REL-4 Tool/Context Interpretation Reliability
REL-5 Regression & Release Stability
```

尤其对 Guardrail LLM 来说，Reliability 不只是“事实正确”，还包括：

```text
same risk → same decision
same policy → same control action
uncertain case → safe escalation
new model version → no regression
```

***

## 3.7 问题七：Benign / Near Restricted 定义还不够可训练

当前文档定义了：

* Restricted：需要被 blocked / filtered；
* Near Restricted：边界模糊；
* Benign：安全，不应被 block；
* Category Specific Benign：与 Safety/Privacy 子类相关的 benign probe；
* Generic Benign：与 restricted category 无关的普通 benign case。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

这是非常好的方向，但还不够训练友好。

Guardrail LLM 训练中，Benign 不应只是“安全样本”，而应细分为：

```text
benign_direct
benign_related
benign_authorized
benign_educational
benign_defensive
benign_fictional_safe
benign_low_risk_tool_use
```

例如，安全研究、合规解释、合法授权测试、隐私流程咨询，都可能包含高风险词汇，但不应被简单拒绝。

### 建议

增加 `intent_context` 字段：

```yaml
intent_context:
  - malicious
  - ambiguous
  - authorized
  - educational
  - defensive
  - administrative
  - personal_data_subject_request
  - fictional
  - compliance_query
```

这对于降低 over-refusal 非常关键。

***

# 4. 面向 Guardrail LLM 训练的结构性修订建议

我建议把 taxonomy 从当前的二维结构：

```text
Category → Subcategory → Threat
```

升级为七维结构：

```text
Risk Category
→ Threat Type
→ Risk Surface
→ Intent Context
→ Severity
→ Control Action
→ Evidence Requirement
```

## 推荐 Schema

```yaml
risk_id: SEC-PI-001
category: SEC
subcategory: Instruction & Policy Integrity
threat: Jailbreak
description: The model violates intended behavior or policy hierarchy under adversarial instruction.
risk_surface:
  - user_input
  - retrieved_context
  - conversation_history
intent_context:
  - malicious
  - ambiguous
severity_default: high
control_actions:
  - refuse
  - safe_complete
  - log
evidence_required:
  - adversarial_instruction_span
  - violated_policy_id
evaluation_metrics:
  - attack_success_rate
  - policy_consistency
  - benign_pass_rate
```

这样才能直接支撑：

* SFT 数据构建；
* DPO chosen/rejected 构造；
* GRPO/RLVR reward design；
* JSON Schema 输出；
* lint rules；
* golden tests；
* release gate。

***

# 5. 建议的重构版 Taxonomy 骨架

## 5.1 Security

```text
SEC-1 Instruction & Policy Integrity
- Jailbreak
- Prompt hierarchy violation
- Goal hijacking
- System instruction override
- Risky exploitable output pattern

SEC-2 Access, Permission & Action Control
- Unauthorized access
- Unauthorized action execution
- Tool-use policy violation
- Approval bypass
- Excessive delegation

SEC-3 Context, Memory & Retrieval Integrity
- Context injection
- Memory poisoning
- Trusted source abuse
- RAG instruction contamination
- Cross-agent instruction hijacking

SEC-4 Availability, Cost & Execution Control
- Runaway execution
- Resource exhaustion
- Denial of service
- Wallet/token drain
- Infinite loop/tool recursion
```

## 5.2 Privacy

```text
PRI-1 Personal Data & PII
- PII disclosure
- Sensitive personal data inference
- Improper retention
- Unauthorized personal data sharing

PRI-2 Secrets & Credentials
- API key leakage
- Password/token leakage
- Internal endpoint/config leakage

PRI-3 Confidential & Proprietary Information
- Business confidential data leakage
- Trade secret exposure
- Source code or internal document exposure

PRI-4 System/Internal Information Exposure
- System prompt disclosure
- Hidden policy disclosure
- Tool schema disclosure
- Internal constraint disclosure

PRI-5 Model & Data Extraction
- Model behavior extraction
- Policy extraction
- Training data regurgitation
- Membership-style leakage

PRI-6 Data Minimization & Vendor Exposure
- Unnecessary sensitive data sent to tools/models/vendors
- Excessive logging
- Cross-tenant data exposure
```

## 5.3 Safety

```text
SAF-1 Physical / Psychological / Financial Harm
- Self-harm unsafe handling
- Violence or dangerous wrongdoing enablement
- Personal safety and rights harm
- Manipulative persuasion

SAF-2 Abuse Enablement
- Cyber abuse enablement
- Fraud or social engineering enablement
- Harassment/extremism-related abuse

SAF-3 Bias, Fairness & Discrimination
- Stereotyping
- Protected-class bias
- Systemic disparity
- Accessibility/disability exclusion
- Generalized discrimination

SAF-4 Content & Jurisdictional Safety
- Age-inappropriate/adult content handling
- Political/public affairs sensitivity
- Geopolitical/national security sensitivity
- Sensitive events/legal proceedings
- Illegal or locally prohibited content

SAF-5 Business Ethics & Market Integrity
- Deception/bribery/corruption support
- Insider misuse/conflict of interest
- Algorithmic power abuse
- Unfair competition
- Commercial compliance risk
```

## 5.4 Reliability

```text
REL-1 Factuality & Grounding
- Factual errors
- Unsupported claims
- Fabricated citations
- Misleading summaries

REL-2 Uncertainty & Deferral
- Overconfident answer
- Safe deferral failure
- Missing caveats in high-impact domain

REL-3 Consistency & Stability
- Inconsistent answers across equivalent prompts
- Long-context contradiction
- Multi-turn policy drift

REL-4 Tool and Context Interpretation
- Misreading tool output
- Misinterpreting retrieved documents
- Using stale or irrelevant evidence

REL-5 Regression & Release Stability
- New version worsens safety metrics
- Guardrail schema instability
- Control action drift
```

***

# 6. 最关键的修订优先级

如果当前要推进 roadmap，我建议优先做 5 件事。

## P0：补上 Control Action

没有 control action，taxonomy 只能用于标注，不能用于 Guardrail runtime。

## P0：补上 Risk Surface

必须区分 input/output/tool\_call/memory/retrieval/system\_state，否则训练和评测会混乱。

## P0：重构 Security

当前 Security 已经很接近 Agent security，但 SEC-1 过宽，建议按 instruction integrity、permission/action、context/memory、availability 重构。

## P1：扩展 Reliability

Reliability 不能只等于 hallucination。对 Guardrail LLM 来说，决策一致性、置信度校准、工具结果解释、版本回归更重要。

## P1：引入 Multi-label 规则

当前文档已说明一个 case 可以多风险标记，且 security 优先出现。 但建议进一步明确： [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
primary_category:
secondary_categories:
risk_priority:
release_gate_dimension:
```

***

# 7. 一句话结论

> **当前 taxonomy 的一级框架是合理的，Security 和 Privacy 的内容尤其有价值；但它仍停留在“风险分类清单”阶段。若要支撑训练增强 Guardrail LLM 和 Enterprise AI Security Control Plane，必须进一步引入 risk surface、intent context、control action、severity、evidence requirement 和 release gate mapping，使其从 taxonomy 升级为可训练、可执行、可评测、可审计的 AI safety/security ontology。**
