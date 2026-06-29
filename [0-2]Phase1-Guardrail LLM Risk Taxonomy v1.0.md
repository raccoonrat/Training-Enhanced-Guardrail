下面给出一份可直接作为 **Guardrail LLM / Enterprise AI Security Control Plane** 使用的完整 Taxonomy。它是在当前 Shared Taxonomy 的四大类 **Security / Privacy / Safety / Reliability** 基础上重构而来；当前版本已经定义了这四类及其初始子类，例如 SEC-1 Policy Compliance、SEC-2 Access & Action Control、PRI-1 PII、PRI-2 IP、SAF-1 Harm、SAF-2 Bias、SAF-3 Content Safety、SAF-4 Business Ethics、REL-1 Hallucinations & Misinformation。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

***

# Guardrail LLM Risk Taxonomy v1.0

## 0. Design Goal

本 Taxonomy 的目标不是一般性的风险罗列，而是支撑以下五类能力：

1. **训练**：用于 SFT / DPO / KTO / GRPO / RLVR 数据构建；
2. **评测**：用于 P0/P1/P2 red-team benchmark 与 release gate；
3. **推理时控制**：用于 runtime guardrail decision；
4. **审计**：用于日志、证据、policy traceability；
5. **治理**：用于企业 AI 安全控制平面、权限治理和合规映射。

***

# 1. Top-Level Categories

```text
SEC - Security
PRI - Privacy
SAF - Safety
REL - Reliability
```

## 1.1 SEC — Security

**Definition**  
AI system, model, agent, toolchain, memory, context, or execution environment remains uncompromised under adversarial or abusive conditions.

**Core concern**  
The system should not be manipulated, hijacked, abused, over-authorized, or forced into unsafe execution.

当前 taxonomy 已将 Security 定义为 AI 在对抗条件下保持未被攻破，并包含 policy compliance、access/action control、availability 等方向。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

***

## 1.2 PRI — Privacy

**Definition**  
Personal, confidential, proprietary, credential, internal, or protected information is minimized, protected, and only used under proper authorization and purpose.

**Core concern**  
The system should not expose, misuse, over-retain, infer, transmit, or reproduce sensitive information.

当前 taxonomy 已将 Privacy 定义为敏感数据保护，并覆盖 PII、personal data、IP、confidential business data、system prompt、model extraction 等风险。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

***

## 1.3 SAF — Safety

**Definition**  
The system should not enable harm, illegality, abuse, discrimination, manipulation, or unethical outcomes.

**Core concern**  
The system should avoid producing or facilitating harmful content, harmful advice, harmful actions, unfair outcomes, or unethical business behavior.

当前 taxonomy 已将 Safety 定义为系统不促成伤害、违法和歧视，并包括 harm、bias、content safety、business ethics 等子类。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

***

## 1.4 REL — Reliability

**Definition**  
The system provides dependable, grounded, calibrated, consistent, and stable outputs and decisions.

**Core concern**  
The system should avoid hallucination, unsupported claims, unstable decisions, overconfidence, tool-result misinterpretation, or release regression.

当前 taxonomy 里 Reliability 主要包括 Hallucinations & Misinformation，但该维度需要扩展到 grounding、uncertainty、consistency、tool interpretation 和 release stability。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

***

# 2. Taxonomy Object Model

建议所有训练样本、评测样本、运行时判定都遵循以下结构。

```yaml
risk_record:
  risk_id: string
  primary_category: SEC | PRI | SAF | REL
  secondary_categories:
    - SEC | PRI | SAF | REL
  subcategory: string
  threat_type: string
  description: string

  risk_surface:
    - user_input
    - model_output
    - tool_call
    - tool_result
    - agent_plan
    - memory
    - retrieval_context
    - system_prompt
    - tool_schema
    - logs
    - external_integration

  intent_context:
    - malicious
    - ambiguous
    - benign
    - authorized
    - defensive
    - educational
    - administrative
    - compliance_query
    - data_subject_request
    - business_operation
    - fictional_or_simulated

  severity:
    default: low | medium | high | critical
    escalation_conditions:
      - string

  control_actions:
    - allow
    - allow_with_constraints
    - safe_complete
    - refuse
    - redact
    - transform
    - escalate
    - block_tool_call
    - require_reauth
    - rate_limit
    - log_only
    - terminate_execution

  evidence_required:
    - risk_span
    - violated_policy_id
    - affected_resource
    - affected_identity
    - tool_name
    - data_type
    - confidence_reason

  evaluation_metrics:
    - risk_recall
    - benign_pass_rate
    - over_refusal_rate
    - attack_success_rate
    - policy_consistency
    - schema_validity
    - evidence_quality
    - regression_delta
```

***

# 3. Control Action Taxonomy

Guardrail LLM 的最终目标不是仅输出风险标签，而是输出可执行控制动作。

```yaml
control_actions:
  allow:
    definition: Request or output is safe and can proceed.
    use_when: No meaningful risk is detected.

  allow_with_constraints:
    definition: Proceed with limited scope, reduced privilege, sandboxing, or additional constraints.
    use_when: Request is legitimate but has elevated operational risk.

  safe_complete:
    definition: Provide safe, high-level, non-enabling, or alternative assistance.
    use_when: User intent may be legitimate, but direct completion could increase risk.

  refuse:
    definition: Do not provide the requested content or action.
    use_when: The request clearly violates policy or enables harm.

  redact:
    definition: Mask or remove sensitive information.
    use_when: Sensitive data is present but the task can proceed after minimization.

  transform:
    definition: Rewrite, summarize, classify, or convert content into a safer form.
    use_when: The original content is risky but a safe transformation is useful.

  escalate:
    definition: Route to human review, compliance review, admin approval, or higher-assurance process.
    use_when: Risk is ambiguous, high-impact, or policy-dependent.

  block_tool_call:
    definition: Prevent tool/API/action execution.
    use_when: The proposed action is unauthorized, destructive, excessive, or unsafe.

  require_reauth:
    definition: Require stronger identity, permission, or approval verification.
    use_when: Action involves sensitive resource, privilege boundary, or data access.

  rate_limit:
    definition: Throttle repeated, expensive, or abusive interactions.
    use_when: Availability, wallet, or automation abuse risk is detected.

  log_only:
    definition: Allow but create audit record.
    use_when: Low-risk but security-relevant event occurs.

  terminate_execution:
    definition: Stop current agent loop, workflow, or execution chain.
    use_when: Runaway execution, recursive tool use, or critical compromise is detected.
```

***

# 4. Risk Surface Taxonomy

```yaml
risk_surfaces:
  user_input:
    description: User-provided prompt, instruction, file, message, or query.

  model_output:
    description: Natural language, code, structured data, or generated artifact from model.

  tool_call:
    description: Function call, API call, command, database operation, file operation, or external action.

  tool_result:
    description: Returned data from tools, APIs, execution environments, or databases.

  agent_plan:
    description: Intermediate reasoning, task plan, workflow graph, or execution plan.

  memory:
    description: Short-term memory, long-term memory, profile memory, vector memory, or cross-session state.

  retrieval_context:
    description: RAG documents, webpages, emails, tickets, database records, or external context.

  system_prompt:
    description: System instructions, hidden policies, developer messages, internal constraints.

  tool_schema:
    description: Tool names, parameters, permissions, schemas, internal APIs, or MCP server definitions.

  logs:
    description: Runtime traces, debug logs, telemetry, prompts, outputs, tool records.

  external_integration:
    description: Third-party services, model vendors, plugins, enterprise SaaS, cloud services.
```

***

# 5. Intent Context Taxonomy

同一个内容在不同语境下风险完全不同。因此每个 case 必须标记 intent context。

```yaml
intent_contexts:
  malicious:
    description: Clear intent to bypass policy, cause harm, steal data, abuse tools, or violate authorization.

  ambiguous:
    description: Intent is unclear, mixed, or insufficiently specified.

  benign:
    description: Ordinary safe request unrelated to restricted categories.

  authorized:
    description: User claims or demonstrates legitimate authority to perform the task.

  defensive:
    description: Request is for protection, detection, hardening, auditing, or incident response.

  educational:
    description: Request is for high-level learning, conceptual explanation, or safe training.

  administrative:
    description: Request is part of normal account, data, system, or workflow administration.

  compliance_query:
    description: Request asks about laws, policies, standards, governance, or risk obligations.

  data_subject_request:
    description: User asks about their own data rights, correction, deletion, access, or consent.

  business_operation:
    description: Request supports legitimate enterprise workflow or productivity task.

  fictional_or_simulated:
    description: Content is framed as fictional, hypothetical, or simulated but may still require safety constraints.
```

***

# 6. Category: Security

## SEC-1 Instruction & Policy Integrity

**Definition**  
Protection of instruction hierarchy, policy boundaries, role integrity, and intended behavior against adversarial manipulation.

当前 taxonomy 中 SEC-1 Policy Compliance 包含 jailbreak、tool-use policy violation、risky outputs、goal hijacking 等 threat；这里将其进一步拆清楚，避免 SEC-1 过宽。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SEC-1:
  name: Instruction & Policy Integrity
  threats:
    SEC-1.1:
      name: Jailbreak
      description: Attempt to bypass safety policy, instruction hierarchy, or behavioral constraints.
      risk_surfaces: [user_input, retrieval_context, memory]
      default_severity: high
      control_actions: [refuse, safe_complete, log_only]

    SEC-1.2:
      name: Prompt Hierarchy Violation
      description: Attempt to override system, developer, or policy-level instructions.
      risk_surfaces: [user_input, retrieval_context, memory, tool_result]
      default_severity: high
      control_actions: [refuse, safe_complete, log_only]

    SEC-1.3:
      name: Goal Hijacking
      description: Agent or model abandons assigned objective and follows an alternative injected goal.
      risk_surfaces: [user_input, retrieval_context, memory, agent_plan]
      default_severity: high
      control_actions: [block_tool_call, terminate_execution, escalate, log_only]

    SEC-1.4:
      name: Role or Authority Impersonation
      description: User or context falsely claims authority, system role, admin status, or internal identity.
      risk_surfaces: [user_input, retrieval_context]
      default_severity: medium
      control_actions: [require_reauth, refuse, escalate]

    SEC-1.5:
      name: Risky Exploitable Output Pattern
      description: Output includes patterns that become exploitable if rendered, executed, parsed, or trusted insecurely.
      risk_surfaces: [model_output, tool_result]
      default_severity: medium
      control_actions: [transform, safe_complete, escalate, log_only]
```

***

## SEC-2 Access, Permission & Action Control

**Definition**  
Protection of resources, tools, data, memory, and actions against unauthorized, excessive, destructive, or out-of-scope access.

当前 taxonomy 中 SEC-2 Access & Action Control 已定义为权限治理，覆盖谁能访问哪些资源、工具、数据、memory 和 action。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SEC-2:
  name: Access, Permission & Action Control
  threats:
    SEC-2.1:
      name: Unauthorized Access
      description: Agent retrieves or accesses resources beyond required or allowed scope.
      risk_surfaces: [tool_call, retrieval_context, memory, external_integration]
      default_severity: high
      control_actions: [block_tool_call, require_reauth, escalate, log_only]

    SEC-2.2:
      name: Unauthorized Action Execution
      description: Agent performs actions outside intended delegation, approval, or authority.
      risk_surfaces: [tool_call, agent_plan]
      default_severity: critical
      control_actions: [block_tool_call, require_reauth, terminate_execution, escalate]

    SEC-2.3:
      name: Destructive Action
      description: Agent performs or attempts destructive operation such as deletion, overwrite, irreversible update, or system mutation.
      risk_surfaces: [tool_call, agent_plan]
      default_severity: critical
      control_actions: [block_tool_call, require_reauth, escalate, log_only]

    SEC-2.4:
      name: Approval Bypass
      description: Agent attempts to skip required human approval, workflow approval, or policy checkpoint.
      risk_surfaces: [agent_plan, tool_call]
      default_severity: high
      control_actions: [block_tool_call, escalate, require_reauth]

    SEC-2.5:
      name: Excessive Delegation
      description: Agent receives or assumes broader authority than necessary for the task.
      risk_surfaces: [system_prompt, tool_schema, agent_plan]
      default_severity: medium
      control_actions: [allow_with_constraints, require_reauth, escalate]
```

***

## SEC-3 Context, Memory & Retrieval Integrity

**Definition**  
Protection of trusted context, retrieved content, memory, and external knowledge sources against poisoning, manipulation, or misuse.

当前 taxonomy 已包含 context & memory integrity abuse，定义为 trusted sources 被污染或滥用并传播到 agent。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SEC-3:
  name: Context, Memory & Retrieval Integrity
  threats:
    SEC-3.1:
      name: Indirect Prompt Injection
      description: External content contains hidden or adversarial instructions intended to manipulate model or agent behavior.
      risk_surfaces: [retrieval_context, tool_result, memory]
      default_severity: high
      control_actions: [transform, safe_complete, block_tool_call, log_only]

    SEC-3.2:
      name: Memory Poisoning
      description: Persistent or short-term memory is manipulated to alter future model behavior.
      risk_surfaces: [memory, user_input, tool_result]
      default_severity: high
      control_actions: [redact, transform, escalate, terminate_execution]

    SEC-3.3:
      name: Trusted Source Abuse
      description: A trusted document, database, email, webpage, or tool result is abused as an instruction carrier.
      risk_surfaces: [retrieval_context, tool_result]
      default_severity: high
      control_actions: [transform, safe_complete, block_tool_call, log_only]

    SEC-3.4:
      name: Cross-Agent Instruction Hijacking
      description: One agent or external actor manipulates another agent through shared context, messages, or coordination channels.
      risk_surfaces: [agent_plan, memory, external_integration]
      default_severity: high
      control_actions: [block_tool_call, terminate_execution, escalate, log_only]

    SEC-3.5:
      name: Context Boundary Confusion
      description: Model fails to distinguish user data, retrieved evidence, instructions, tool results, and system policy.
      risk_surfaces: [retrieval_context, user_input, tool_result, system_prompt]
      default_severity: medium
      control_actions: [safe_complete, transform, escalate]
```

***

## SEC-4 Availability, Cost & Execution Control

**Definition**  
Protection against runaway execution, resource exhaustion, abusive usage, wallet drain, denial of service, and unstable execution.

当前 taxonomy 中 SEC-3 Availability 已覆盖 product 可访问、响应和运行能力，并列出 runaway execution、resource exhaustion、DoS/wallet 等 threat。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SEC-4:
  name: Availability, Cost & Execution Control
  threats:
    SEC-4.1:
      name: Runaway Execution
      description: Agent enters uncontrolled, recursive, or self-reinforcing execution loop.
      risk_surfaces: [agent_plan, tool_call]
      default_severity: high
      control_actions: [terminate_execution, rate_limit, log_only]

    SEC-4.2:
      name: Resource Exhaustion
      description: Behavior consumes excessive compute, memory, storage, bandwidth, tokens, or execution time.
      risk_surfaces: [tool_call, model_output, agent_plan]
      default_severity: high
      control_actions: [rate_limit, terminate_execution, block_tool_call]

    SEC-4.3:
      name: Denial of Service
      description: Interaction pattern degrades or disables service availability.
      risk_surfaces: [user_input, tool_call, external_integration]
      default_severity: high
      control_actions: [rate_limit, block_tool_call, escalate]

    SEC-4.4:
      name: Wallet or Token Drain
      description: Abusive or uncontrolled behavior causes excessive financial, API, token, or cloud cost.
      risk_surfaces: [agent_plan, tool_call]
      default_severity: high
      control_actions: [rate_limit, terminate_execution, escalate]

    SEC-4.5:
      name: Unsafe Long-Running Task
      description: Agent continues task beyond safe timeout, scope, or budget.
      risk_surfaces: [agent_plan, tool_call]
      default_severity: medium
      control_actions: [allow_with_constraints, terminate_execution, escalate]
```

***

# 7. Category: Privacy

## PRI-1 Personal Data & PII

当前 taxonomy 中 PRI-1 已定义为 handling identifiable, sensitive, or user-related personal information across inputs, outputs, memory, logs, and integrations。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
PRI-1:
  name: Personal Data & PII
  threats:
    PRI-1.1:
      name: Direct PII Disclosure
      description: Model outputs identifiable personal data without proper authorization or purpose.
      risk_surfaces: [model_output, tool_result, logs]
      default_severity: high
      control_actions: [redact, refuse, escalate, log_only]

    PRI-1.2:
      name: Sensitive Personal Data Inference
      description: Model infers sensitive personal attributes from context or indirect signals.
      risk_surfaces: [model_output, retrieval_context, memory]
      default_severity: high
      control_actions: [safe_complete, refuse, redact]

    PRI-1.3:
      name: Improper Personal Data Retention
      description: Personal data is stored in memory, logs, or integrations without valid need.
      risk_surfaces: [memory, logs, external_integration]
      default_severity: medium
      control_actions: [redact, transform, escalate]

    PRI-1.4:
      name: Unauthorized Personal Data Sharing
      description: Personal data is sent or exposed to unauthorized user, model, tool, vendor, or tenant.
      risk_surfaces: [tool_call, external_integration, model_output]
      default_severity: critical
      control_actions: [block_tool_call, redact, escalate]
```

***

## PRI-2 Secrets & Credentials

当前 taxonomy 已单独列出 secrets/credentials disclosure，包括 tokens、passwords、keys、internal endpoints/configs。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
PRI-2:
  name: Secrets & Credentials
  threats:
    PRI-2.1:
      name: API Key or Token Leakage
      description: API keys, access tokens, session tokens, or auth headers are exposed.
      risk_surfaces: [model_output, logs, tool_result, memory]
      default_severity: critical
      control_actions: [redact, refuse, escalate, log_only]

    PRI-2.2:
      name: Password or Credential Leakage
      description: Passwords, secrets, certificates, or private keys are exposed.
      risk_surfaces: [model_output, logs, memory]
      default_severity: critical
      control_actions: [redact, refuse, escalate]

    PRI-2.3:
      name: Internal Endpoint or Configuration Exposure
      description: Internal URLs, infrastructure configs, access paths, or deployment details are exposed.
      risk_surfaces: [model_output, tool_result, logs]
      default_severity: high
      control_actions: [redact, safe_complete, escalate]
```

***

## PRI-3 Confidential & Proprietary Information

当前 taxonomy 中 PRI-2 IP / Intellectual Property 覆盖 proprietary information、confidential business data、trade secrets、source code、internal documents、protected third-party content。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
PRI-3:
  name: Confidential & Proprietary Information
  threats:
    PRI-3.1:
      name: Confidential Business Data Leakage
      description: Internal documents, customer information, trade secrets, or sensitive operational details are exposed.
      risk_surfaces: [model_output, retrieval_context, tool_result, logs]
      default_severity: high
      control_actions: [redact, refuse, escalate]

    PRI-3.2:
      name: Source Code or Internal Artifact Exposure
      description: Proprietary code, design documents, architecture, or internal artifacts are reproduced or exposed.
      risk_surfaces: [model_output, retrieval_context, tool_result]
      default_severity: high
      control_actions: [redact, safe_complete, escalate]

    PRI-3.3:
      name: Protected Third-Party Content Reproduction
      description: Protected external content is reproduced beyond allowed use.
      risk_surfaces: [model_output, retrieval_context]
      default_severity: medium
      control_actions: [safe_complete, transform, refuse]
```

***

## PRI-4 System & Internal Instruction Exposure

当前 taxonomy 将 system prompt / hidden instruction disclosure 放在 Privacy/IP 下，包含 system prompts、hidden policies、tool schemas、internal constraints。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
PRI-4:
  name: System & Internal Instruction Exposure
  secondary_categories: [SEC]
  threats:
    PRI-4.1:
      name: System Prompt Disclosure
      description: System prompt or hidden instruction is exposed.
      risk_surfaces: [model_output, system_prompt, logs]
      default_severity: high
      control_actions: [refuse, redact, safe_complete, log_only]

    PRI-4.2:
      name: Hidden Policy Disclosure
      description: Internal policy logic, hidden refusal rules, or safety constraints are exposed.
      risk_surfaces: [model_output, system_prompt, logs]
      default_severity: high
      control_actions: [refuse, safe_complete, log_only]

    PRI-4.3:
      name: Tool Schema Disclosure
      description: Internal tool names, schemas, parameters, or privileged API details are exposed.
      risk_surfaces: [model_output, tool_schema, logs]
      default_severity: high
      control_actions: [redact, refuse, escalate]
```

***

## PRI-5 Model, Policy & Data Extraction

当前 taxonomy 中 Privacy threats 已包含 model extraction 和 training/IP regurgitation。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
PRI-5:
  name: Model, Policy & Data Extraction
  secondary_categories: [SEC]
  threats:
    PRI-5.1:
      name: Model Behavior Extraction
      description: Repeated probing attempts to replicate protected model behavior.
      risk_surfaces: [user_input, model_output, logs]
      default_severity: medium
      control_actions: [rate_limit, safe_complete, log_only]

    PRI-5.2:
      name: Policy Logic Extraction
      description: Attempts to infer internal guardrail rules, thresholds, or policy decision boundaries.
      risk_surfaces: [user_input, model_output]
      default_severity: high
      control_actions: [safe_complete, refuse, rate_limit, log_only]

    PRI-5.3:
      name: Training Data Regurgitation
      description: Model reproduces memorized protected or sensitive training content.
      risk_surfaces: [model_output]
      default_severity: high
      control_actions: [redact, safe_complete, escalate]
```

***

## PRI-6 Data Minimization & Vendor Exposure

当前 taxonomy 明确包含 unnecessary sensitive data sent to models/tools。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
PRI-6:
  name: Data Minimization & Vendor Exposure
  threats:
    PRI-6.1:
      name: Unnecessary Sensitive Data Transmission
      description: More sensitive data than needed is sent to models, tools, vendors, or plugins.
      risk_surfaces: [tool_call, external_integration, logs]
      default_severity: medium
      control_actions: [redact, transform, allow_with_constraints]

    PRI-6.2:
      name: Excessive Logging
      description: Sensitive prompts, outputs, tool results, or user data are logged unnecessarily.
      risk_surfaces: [logs]
      default_severity: medium
      control_actions: [redact, transform, escalate]

    PRI-6.3:
      name: Cross-Tenant Exposure
      description: Data from one tenant, user, project, or authority boundary is exposed to another.
      risk_surfaces: [memory, retrieval_context, tool_result, model_output]
      default_severity: critical
      control_actions: [refuse, redact, escalate, terminate_execution]
```

***

# 8. Category: Safety

## SAF-1 Human Harm & Personal Rights

当前 taxonomy 中 SAF-1 Harm 覆盖 physical、psychological、financial、operational、societal harm，并在 threat breakdown 中列出 self-harm assistance、violence/criminal wrongdoing enablement、personal safety and rights harm、manipulative persuasion 等。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SAF-1:
  name: Human Harm & Personal Rights
  threats:
    SAF-1.1:
      name: Self-Harm Unsafe Handling
      description: Unsafe response to self-harm ideation, emotional crisis, or vulnerable-user situation.
      risk_surfaces: [user_input, model_output]
      default_severity: critical
      control_actions: [safe_complete, escalate, log_only]

    SAF-1.2:
      name: Violence or Dangerous Wrongdoing Enablement
      description: Assistance that enables physical harm or dangerous wrongdoing.
      risk_surfaces: [user_input, model_output, tool_call]
      default_severity: critical
      control_actions: [refuse, safe_complete, log_only]

    SAF-1.3:
      name: Personal Safety and Rights Harm
      description: Support for stalking, doxxing, intimidation, coercion, reputation harm, or violation of personal rights.
      risk_surfaces: [user_input, model_output, tool_call]
      default_severity: high
      control_actions: [refuse, safe_complete, escalate]

    SAF-1.4:
      name: Manipulative Persuasion
      description: Coercive or exploitative persuasion, especially involving vulnerable people or high-impact decisions.
      risk_surfaces: [user_input, model_output]
      default_severity: high
      control_actions: [safe_complete, refuse, escalate]
```

***

## SAF-2 Abuse Enablement

当前 taxonomy 将 cybercrime/malware enablement、fraud/social engineering enablement、hate/extremism/harassment 等放在 Harm 下。这里将其抽象为 Abuse Enablement，便于与 Security 做 secondary mapping。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SAF-2:
  name: Abuse Enablement
  secondary_categories: [SEC]
  threats:
    SAF-2.1:
      name: Cyber Abuse Enablement
      description: Assistance enabling unauthorized cyber abuse, exploitation, malware, evasion, or intrusion.
      risk_surfaces: [user_input, model_output, tool_call]
      default_severity: critical
      control_actions: [refuse, safe_complete, log_only]

    SAF-2.2:
      name: Fraud or Social Engineering Enablement
      description: Assistance enabling scams, deception, impersonation, phishing, or social engineering.
      risk_surfaces: [user_input, model_output, tool_call]
      default_severity: critical
      control_actions: [refuse, safe_complete, escalate]

    SAF-2.3:
      name: Hate, Extremism or Targeted Harassment
      description: Content that enables targeted harassment, extremist support, or hateful abuse.
      risk_surfaces: [user_input, model_output]
      default_severity: high
      control_actions: [refuse, safe_complete, log_only]
```

***

## SAF-3 Bias, Fairness & Inclusion

当前 taxonomy 中 SAF-2 Bias 覆盖 fairness、stereotyping、discrimination、disparate outcomes，并列出 stereotyping、systemic bias、protected-class bias、accessibility exclusion、generalized discrimination。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SAF-3:
  name: Bias, Fairness & Inclusion
  threats:
    SAF-3.1:
      name: Stereotyping
      description: Assumptions, judgments, or recommendations based on generalized group stereotypes.
      risk_surfaces: [model_output]
      default_severity: medium
      control_actions: [transform, safe_complete, escalate]

    SAF-3.2:
      name: Protected-Class Bias
      description: Unfair treatment based on sensitive or protected traits.
      risk_surfaces: [model_output, agent_plan, tool_call]
      default_severity: high
      control_actions: [transform, safe_complete, escalate]

    SAF-3.3:
      name: Systemic Disparate Outcome
      description: Repeated unequal quality, tone, recommendations, risk judgments, or opportunities across groups.
      risk_surfaces: [model_output, logs, evaluation_results]
      default_severity: high
      control_actions: [escalate, transform, log_only]

    SAF-3.4:
      name: Accessibility or Disability Exclusion
      description: System excludes, disadvantages, or fails to accommodate users with disabilities or accessibility needs.
      risk_surfaces: [model_output, user_experience, tool_call]
      default_severity: medium
      control_actions: [transform, safe_complete, escalate]

    SAF-3.5:
      name: Generalized Discrimination
      description: Unfair outcomes based on meaningful non-protected attributes such as geography, income, education, job status, or appearance.
      risk_surfaces: [model_output, agent_plan]
      default_severity: medium
      control_actions: [transform, escalate, log_only]
```

***

## SAF-4 Content & Jurisdictional Safety

当前 taxonomy 中 SAF-3 Content Safety 包括 prohibited、inappropriate、offensive、explicit 或 disallowed content；threat breakdown 还包括 political/public affairs、geopolitical/national security、sensitive events/legal proceedings、illegal/locally prohibited content。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SAF-4:
  name: Content & Jurisdictional Safety
  threats:
    SAF-4.1:
      name: Age-Inappropriate or Explicit Content Policy Risk
      description: Content violates age-appropriateness, explicit-content, exploitation, or related content-safety policy.
      risk_surfaces: [user_input, model_output]
      default_severity: high
      control_actions: [refuse, safe_complete, log_only]

    SAF-4.2:
      name: Political or Public Affairs Sensitivity
      description: Mishandling of elections, civic participation, public policy, public figures, or political persuasion.
      risk_surfaces: [user_input, model_output]
      default_severity: medium
      control_actions: [safe_complete, transform, escalate]

    SAF-4.3:
      name: Geopolitical or National Security Sensitivity
      description: Unsafe, inflammatory, misleading, or unsupported handling of conflicts, sanctions, military, intelligence, or state-sensitive topics.
      risk_surfaces: [user_input, model_output]
      default_severity: high
      control_actions: [safe_complete, escalate, log_only]

    SAF-4.4:
      name: Sensitive Events or Legal Proceedings
      description: Fabricated, sensationalized, or harmful unsupported claims about crises, tragedies, investigations, lawsuits, or legal proceedings.
      risk_surfaces: [model_output]
      default_severity: high
      control_actions: [safe_complete, transform, escalate]

    SAF-4.5:
      name: Illegal or Locally Prohibited Content
      description: Guidance, facilitation, or encouragement for activities restricted by local law, regulation, or jurisdiction-specific rules.
      risk_surfaces: [user_input, model_output, tool_call]
      default_severity: high
      control_actions: [refuse, safe_complete, escalate]
```

***

## SAF-5 Business Ethics & Market Integrity

当前 taxonomy 中 SAF-4 Business Ethics 包括 deception、fraud、manipulation、rights infringement 和 misuse of confidential information；threat breakdown 进一步包括 business ethics violation、algorithmic power abuse、commercial compliance risk。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
SAF-5:
  name: Business Ethics & Market Integrity
  threats:
    SAF-5.1:
      name: Business Ethics Violation
      description: Support for deception, bribery, corruption, insider misuse, conflicts of interest, falsification, or unethical professional conduct.
      risk_surfaces: [user_input, model_output, tool_call]
      default_severity: high
      control_actions: [refuse, safe_complete, escalate]

    SAF-5.2:
      name: Algorithmic Power Abuse or Unfair Competition
      description: Manipulation of rankings, reviews, ads, platforms, competitors, customers, or markets through unfair or deceptive methods.
      risk_surfaces: [user_input, model_output, tool_call]
      default_severity: high
      control_actions: [refuse, safe_complete, escalate]

    SAF-5.3:
      name: Commercial Compliance Risk
      description: Risky claims, actions, or advice in regulated, contractual, advertising, procurement, sanctions, or consumer protection contexts.
      risk_surfaces: [model_output, tool_call, external_integration]
      default_severity: high
      control_actions: [safe_complete, escalate, log_only]
```

***

# 9. Category: Reliability

## REL-1 Factuality & Grounding

当前 taxonomy 中 REL-1 Hallucinations & Misinformation 关注 accuracy、grounding、truthfulness、claims、evidence、recommendations、confidence。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
REL-1:
  name: Factuality & Grounding
  threats:
    REL-1.1:
      name: Factual Error
      description: Output contains incorrect facts in decision-impacting or sensitive context.
      risk_surfaces: [model_output]
      default_severity: medium
      control_actions: [safe_complete, transform, escalate]

    REL-1.2:
      name: Unsupported Claim
      description: Output makes claims without sufficient evidence, grounding, or source support.
      risk_surfaces: [model_output]
      default_severity: medium
      control_actions: [transform, safe_complete]

    REL-1.3:
      name: Fabricated Citation or Source
      description: Output invents source, citation, reference, document, or evidence.
      risk_surfaces: [model_output]
      default_severity: high
      control_actions: [transform, safe_complete, escalate]

    REL-1.4:
      name: Misleading Summary
      description: Output distorts, omits, or misrepresents material facts in summarized content.
      risk_surfaces: [model_output, retrieval_context]
      default_severity: medium
      control_actions: [transform, escalate]
```

***

## REL-2 Uncertainty, Calibration & Deferral

当前 taxonomy 中 Reliability threat 包含 safe deferral failing，即在应该避免回答的话题上失败。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

```yaml
REL-2:
  name: Uncertainty, Calibration & Deferral
  threats:
    REL-2.1:
      name: Overconfident Answer
      description: Model provides high-confidence answer despite insufficient evidence or high uncertainty.
      risk_surfaces: [model_output]
      default_severity: medium
      control_actions: [safe_complete, transform]

    REL-2.2:
      name: Safe Deferral Failure
      description: Model fails to defer, qualify, or escalate when topic requires caution, expertise, authorization, or review.
      risk_surfaces: [model_output, tool_call]
      default_severity: high
      control_actions: [safe_complete, escalate]

    REL-2.3:
      name: Missing Caveat in High-Impact Context
      description: Output lacks appropriate caveat, uncertainty, limitation, or recommendation to seek qualified review.
      risk_surfaces: [model_output]
      default_severity: medium
      control_actions: [safe_complete, transform]
```

***

## REL-3 Consistency & Stability

```yaml
REL-3:
  name: Consistency & Stability
  threats:
    REL-3.1:
      name: Equivalent Prompt Inconsistency
      description: Similar or semantically equivalent prompts produce materially different safety decisions.
      risk_surfaces: [model_output, evaluation_results]
      default_severity: medium
      control_actions: [log_only, escalate]

    REL-3.2:
      name: Multi-Turn Policy Drift
      description: Model changes safety stance across conversation turns without relevant new evidence.
      risk_surfaces: [conversation_history, model_output]
      default_severity: high
      control_actions: [safe_complete, escalate, log_only]

    REL-3.3:
      name: Long-Context Contradiction
      description: Model contradicts earlier constraints, facts, approvals, or denials in long context.
      risk_surfaces: [retrieval_context, memory, model_output]
      default_severity: medium
      control_actions: [transform, escalate]
```

***

## REL-4 Tool & Context Interpretation Reliability

```yaml
REL-4:
  name: Tool & Context Interpretation Reliability
  threats:
    REL-4.1:
      name: Tool Result Misinterpretation
      description: Model misunderstands, over-trusts, or misuses tool output.
      risk_surfaces: [tool_result, model_output, agent_plan]
      default_severity: high
      control_actions: [safe_complete, escalate, block_tool_call]

    REL-4.2:
      name: Retrieved Evidence Misuse
      description: Model uses stale, irrelevant, low-quality, or contradictory retrieved evidence.
      risk_surfaces: [retrieval_context, model_output]
      default_severity: medium
      control_actions: [transform, safe_complete, escalate]

    REL-4.3:
      name: Context-Instruction Confusion
      description: Model treats untrusted context as instruction or treats instruction as evidence.
      risk_surfaces: [retrieval_context, user_input, system_prompt]
      default_severity: high
      control_actions: [safe_complete, transform, log_only]
```

***

## REL-5 Regression & Release Stability

```yaml
REL-5:
  name: Regression & Release Stability
  threats:
    REL-5.1:
      name: Safety Metric Regression
      description: New model, policy, prompt, or guardrail version worsens safety metrics relative to baseline.
      risk_surfaces: [evaluation_results]
      default_severity: high
      control_actions: [escalate, terminate_execution]

    REL-5.2:
      name: Schema Instability
      description: Guardrail output violates expected schema, field names, decision enum, or compatibility contract.
      risk_surfaces: [model_output]
      default_severity: medium
      control_actions: [transform, escalate]

    REL-5.3:
      name: Control Action Drift
      description: Same risk condition maps to inconsistent control actions across versions or contexts.
      risk_surfaces: [model_output, evaluation_results]
      default_severity: high
      control_actions: [escalate, log_only]
```

***

# 10. Multi-Label and Priority Rules

当前 taxonomy 已说明一个 test case 可能具有多个风险类别，并建议 Security 优先出现，例如数据库访问和财务数据返回可同时标记 SEC-2 和 PRI-1。 [\[Shared Tax...nomy (NEW) \| PDF\]](https://lenovo-my.sharepoint.com/personal/wangyh43_lenovo_com/Documents/Microsoft%20Copilot%20%E8%81%8A%E5%A4%A9%E6%96%87%E4%BB%B6/Shared%20Taxonomy%20(NEW).pdf)

建议正式化为以下规则。

```yaml
multi_label_rules:
  rule_1:
    name: Primary Category
    description: The primary category should represent the dominant failure mode that requires the strongest control action.

  rule_2:
    name: Secondary Categories
    description: Secondary categories should capture additional harm, privacy, reliability, or security consequences.

  rule_3:
    name: Security Priority
    description: If a case includes unauthorized access, unauthorized action, tool abuse, or agent compromise, SEC should usually be primary.

  rule_4:
    name: Privacy Priority
    description: If sensitive data is actually exposed, PRI must be included even when SEC or SAF is primary.

  rule_5:
    name: Safety Priority
    description: If the main outcome is harm enablement, abuse, discrimination, or unethical conduct, SAF should be primary.

  rule_6:
    name: Reliability as Amplifier
    description: REL may be primary for factuality failures, but often acts as a secondary amplifier when misinformation increases SEC, PRI, or SAF risk.
```

***

# 11. Severity Model

```yaml
severity_levels:
  low:
    definition: Minimal or recoverable risk; no sensitive data, no action execution, no high-impact domain.
    default_controls: [allow, log_only]

  medium:
    definition: Meaningful risk that may mislead, inconvenience, expose low-sensitivity information, or create limited operational impact.
    default_controls: [safe_complete, transform, log_only]

  high:
    definition: Significant risk involving sensitive data, unauthorized access, harmful enablement, high-impact decision, or policy bypass.
    default_controls: [refuse, redact, block_tool_call, escalate]

  critical:
    definition: Severe risk involving destructive action, credential exposure, cross-tenant leakage, imminent harm, or system compromise.
    default_controls: [refuse, block_tool_call, terminate_execution, escalate]
```

***

# 12. Guardrail Output Schema

建议 Guardrail LLM 强制输出以下 JSON 风格结构。

```json
{
  "decision": "allow | allow_with_constraints | safe_complete | refuse | redact | transform | escalate | block_tool_call | require_reauth | rate_limit | log_only | terminate_execution",
  "primary_category": "SEC | PRI | SAF | REL",
  "secondary_categories": ["SEC", "PRI"],
  "risk_ids": ["SEC-2.2", "PRI-2.1"],
  "severity": "low | medium | high | critical",
  "confidence": 0.0,
  "risk_surface": ["user_input", "tool_call"],
  "intent_context": "malicious | ambiguous | benign | authorized | defensive | educational | administrative | compliance_query | data_subject_request | business_operation | fictional_or_simulated",
  "evidence": [
    {
      "type": "risk_span | policy_reference | affected_resource | tool_name | data_type",
      "value": "string"
    }
  ],
  "policy_references": ["POLICY-ID"],
  "recommended_safe_response": "string",
  "audit_required": true,
  "human_review_required": false
}
```

***

# 13. Release Gate Metrics

```yaml
release_gate_metrics:
  global:
    schema_validity: ">= 99%"
    critical_findings: "== 0"
    high_risk_regression: "<= 0"
    policy_consistency: ">= 95%"

  security:
    jailbreak_attack_success_rate: "<= target_threshold"
    unauthorized_tool_call_block_rate: ">= 98%"
    goal_hijacking_block_rate: ">= 95%"
    runaway_execution_detection_rate: ">= 95%"

  privacy:
    pii_leakage_rate: "<= target_threshold"
    credential_leakage_rate: "== 0"
    system_prompt_disclosure_rate: "== 0"
    unnecessary_data_transmission_detection_rate: ">= 95%"

  safety:
    harmful_enablement_block_rate: ">= 95%"
    abuse_enablement_block_rate: ">= 95%"
    bias_detection_coverage: ">= target_threshold"
    business_ethics_violation_block_rate: ">= 90%"

  reliability:
    factuality_pass_rate: ">= target_threshold"
    citation_fabrication_rate: "<= target_threshold"
    equivalent_prompt_consistency: ">= 95%"
    control_action_drift: "<= target_threshold"
```

***

# 14. Final Compact View

```text
SEC Security
├── SEC-1 Instruction & Policy Integrity
│   ├── Jailbreak
│   ├── Prompt Hierarchy Violation
│   ├── Goal Hijacking
│   ├── Role or Authority Impersonation
│   └── Risky Exploitable Output Pattern
├── SEC-2 Access, Permission & Action Control
│   ├── Unauthorized Access
│   ├── Unauthorized Action Execution
│   ├── Destructive Action
│   ├── Approval Bypass
│   └── Excessive Delegation
├── SEC-3 Context, Memory & Retrieval Integrity
│   ├── Indirect Prompt Injection
│   ├── Memory Poisoning
│   ├── Trusted Source Abuse
│   ├── Cross-Agent Instruction Hijacking
│   └── Context Boundary Confusion
└── SEC-4 Availability, Cost & Execution Control
    ├── Runaway Execution
    ├── Resource Exhaustion
    ├── Denial of Service
    ├── Wallet or Token Drain
    └── Unsafe Long-Running Task

PRI Privacy
├── PRI-1 Personal Data & PII
├── PRI-2 Secrets & Credentials
├── PRI-3 Confidential & Proprietary Information
├── PRI-4 System & Internal Instruction Exposure
├── PRI-5 Model, Policy & Data Extraction
└── PRI-6 Data Minimization & Vendor Exposure

SAF Safety
├── SAF-1 Human Harm & Personal Rights
├── SAF-2 Abuse Enablement
├── SAF-3 Bias, Fairness & Inclusion
├── SAF-4 Content & Jurisdictional Safety
└── SAF-5 Business Ethics & Market Integrity

REL Reliability
├── REL-1 Factuality & Grounding
├── REL-2 Uncertainty, Calibration & Deferral
├── REL-3 Consistency & Stability
├── REL-4 Tool & Context Interpretation Reliability
└── REL-5 Regression & Release Stability
```

***

# 15. One-Sentence Positioning

> **这份 Taxonomy 将原有 Security / Privacy / Safety / Reliability 四类风险，从“人工风险清单”升级为可训练、可评测、可执行、可审计的 Guardrail LLM 安全本体：每个风险不仅有类别和定义，还绑定 risk surface、intent context、severity、control action、evidence requirement 与 release gate metric。**
