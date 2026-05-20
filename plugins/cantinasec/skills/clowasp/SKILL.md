---
name: clowasp
description: Audit an AI agent pipeline against the OWASP Top 10 for Agentic Applications 2026. Reconstructs pipeline topology from CrewAI / n8n / LangGraph / AutoGen / Flowise / Python / plain-text descriptions, scores every agent and connection against ASI01–ASI10, and returns PASS / REVIEW / BLOCK with drop-in remediations.
---

# clowasp — OWASP Agentic Top 10 Auditor

Pre-deployment audit for AI agent pipelines, grounded in the **OWASP Top 10 for Agentic Applications 2026**. The skill is deterministic about topology reconstruction and prescriptive about remediation — every finding ships with a complete drop-in fix, never generic advice.

Verdict is **PASS**, **REVIEW**, or **BLOCK**.

## When to use this skill

A Cantina security engineer, auditor, or pipeline owner asks any of:
- "Audit my agent pipeline"
- "Run OWASP Agentic on this crew"
- "Is this n8n workflow safe to ship?"
- "Check this CrewAI / LangGraph / AutoGen setup"
- "What's the risk on this multi-agent system?"
- "Score this pipeline against ASI01–ASI10"

If the user only wants to scan for prompt injection, defer to `/cantinasec:inject` (focused ASI01 sub-audit).

## Supported pipeline formats

- **CrewAI** — `crew.py`, `agents.yaml`, `tasks.yaml`, decorators (`@agent`, `@task`, `@crew`)
- **n8n** — exported workflow JSON (`nodes` + `connections`)
- **LangGraph** — `StateGraph`, `add_node`, `add_edge`
- **AutoGen** — `AssistantAgent`, `UserProxyAgent`, `GroupChat`
- **Flowise** — exported chatflow JSON
- **Plain Python** — any file describing agents, tools, and edges
- **YAML / JSON** — any pipeline descriptor with a recognizable topology
- **Plain text** — free-form description if no file is available

## Input resolution

If `$ARGUMENTS` is provided:
- **File path** → read the file and infer the framework
- **Python code** (contains `Agent(`, `@agent`, `crewai`, `langgraph`, `autogen`) → parse as code
- **JSON** → detect n8n (`nodes` + `connections`), CrewAI (`agents` array), or Flowise (`chatflow`)
- **YAML** → parse as CrewAI agents/tasks
- **Plain text** → treat as a pipeline description

If no arguments are provided:
1. Search the working directory for likely pipeline files: `crew.py`, `agents.yaml`, `tasks.yaml`, `*.json` workflows, anything containing `Agent(`, `@agent`, `crewai`, `langgraph`, `autogen`, `n8n`.
2. Combine multiple files to reconstruct full topology (e.g. `agents.yaml` + `tasks.yaml` + `crew.py`).
3. If nothing is found, ask the user to paste their pipeline or describe it in plain text.

## The 10 risks (OWASP Agentic 2026)

For every agent and every connection in the reconstructed topology, evaluate:

| ID | Risk | What to look for |
|---|---|---|
| **ASI01** | Agent Goal Hijack (prompt injection) | Raw interpolation of untrusted input; tool outputs (web fetch, search, file read) flowing into reasoning context without delimiters or instruction-pattern filtering; cross-agent propagation where one agent's output becomes another's instruction |
| **ASI02** | Excessive Agency | Agents with destructive tools (file write, shell, API write, payments, email send) and no human-in-the-loop gate; `allow_delegation: true` with no scope; unbounded `max_iter` |
| **ASI03** | Insecure Tool Use | Tools that execute code, run shell, or hit arbitrary URLs without allowlists, sandboxing, or output filtering |
| **ASI04** | Supply Chain & Dependency Risk | Runtime package install (`pip install` at task time), MCP servers loaded from untrusted registries, sub-agents pulled from URLs, unpinned model versions, plugins fetched at runtime |
| **ASI05** | Identity & Authentication Drift | Agents acting on behalf of users without scoped credentials; shared service accounts; secrets baked into prompts or tools |
| **ASI06** | Memory Poisoning | Persistent memory or RAG stores written by agents that ingest untrusted content; no provenance on memory entries; long-term memory read back into reasoning context without trust labels |
| **ASI07** | Output Handling Failures | Agent output passed to `eval`, `exec`, SQL, shell, or rendered HTML without escaping; structured outputs (JSON, function calls) parsed without schema validation |
| **ASI08** | Resource Exhaustion & Cost | Unbounded loops (`max_iter` missing or huge), recursive delegation, no spend caps, no per-agent timeout |
| **ASI09** | Fabricated Rationale | Agents producing justifications for destructive actions with no grounding requirement; "explain your reasoning then act" patterns where the explanation is not verified |
| **ASI10** | Rogue Agents | Uncontrolled agent spawning (`allow_delegation: true` + `spawn_agent` tools), goal drift across iterations, sub-agents that can spawn further sub-agents |

For each finding, capture: which node, which risk, severity (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`), and the exact line/key/field that triggers it.

## Verdict logic

- **BLOCK** — any `CRITICAL` finding, or two or more `HIGH` findings on the same node
- **REVIEW** — any `HIGH` finding, or three or more `MEDIUM` findings across the pipeline
- **PASS** — only `LOW` / `NA` findings

Be honest. Don't soften a `BLOCK` because the pipeline looks polished, and don't escalate a `REVIEW` to a `BLOCK` to look thorough.

## Output format

```
# Cantina clowasp — [pipeline name]

**Verdict:** PASS | REVIEW | BLOCK
**Framework:** [CrewAI / n8n / LangGraph / …]
**Topology:** [N agents, M connections, K tools]

## Findings

For each finding:

---
**[ASI0X] [node name]** · CRITICAL | HIGH | MEDIUM | LOW

[One sentence: exactly what is wrong on this node and how it is reachable.]

```yaml
# [node name] — drop-in replacement for agents.yaml / tasks.yaml / crew.py / workflow.json
[Complete fix. Adds the specific guard this node needs — input sanitization,
human-approval gate, tool allowlist, max_iter cap, memory provenance, output
schema, whatever the risk demands. Never generic.]
```
---

## Attack chain

[If multiple findings chain together, describe the full propagation path in 2–3 sentences:
entry point → how the payload or escalation moves → blast radius.]

## Priority fixes

1. [Most urgent — one line, names the node and the risk]
2. [Second — one line]
3. [Third — one line]
```

## Rules

- **Be specific to this pipeline.** Cite the actual agent name, role, tool name, or n8n node ID. Never generic OWASP language.
- **Every finding ships with a drop-in fix.** No "consider adding sanitization" — write the sanitization.
- **Only report reachable risks.** If untrusted input cannot reach a node, do not flag it.
- **Group by node, not by risk.** A single node hitting ASI01 + ASI06 + ASI10 gets one combined fix block, not three.
- **The verdict is one of three values.** Never "PASS with caveats" or "BLOCK pending review" — pick one and justify it.

## Related skills

- `/cantinasec:inject` — focused ASI01 sub-audit when the user only cares about prompt injection
- `/cantinasec:tripwire` — broader agentic-pipeline audit against the same OWASP 2026 list, useful as a second opinion
- `/cantinasec:clawtsuite` — audits installed Claude skills (not pipelines) against Cantina's 6-point standard

Source: https://github.com/aidan269/clowasp
