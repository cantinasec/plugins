---
name: clowasp
description: Drive the clowasp `audit.py` CLI to audit an LLM/agent prompt — system prompt, tool description, MCP config, or agent instruction — against the OWASP Top 10 for Agentic Applications 2026. Scores ASI01 (goal hijack), ASI04 (supply chain), ASI06 (memory poisoning), ASI09 (fabricated rationale), and ASI10 (rogue agents); returns PASS / REVIEW / BLOCK and a drop-in safe rewrite of the original prompt.
---

# clowasp — Agentic Prompt Auditor

Pre-deployment audit for AI agent prompts, grounded in the **OWASP Top 10 for Agentic Applications 2026** (five net-new risks that web2 security tooling does not cover).

This skill is a thin wrapper around the [aidan269/clowasp](https://github.com/aidan269/clowasp) `audit.py` CLI — clone, locate, run, surface the result. It does not re-implement the audit in-skill.

## When to use this skill

A Cantina security engineer, prompt author, or pipeline owner asks any of:
- "Is this prompt safe to ship?"
- "Audit my agent's system prompt"
- "Check this MCP config / tool description before I install it"
- "Score this prompt against OWASP Agentic"
- "Run clowasp on `<prompt or file>`"

If the user wants to audit the **topology** of a multi-agent workflow (CrewAI / n8n / LangGraph), defer to `/cantinasec:inject` (focused ASI01 sub-audit) or `/cantinasec:tripwire` (broader agentic-pipeline audit). `clowasp` audits a **single prompt string**, not a pipeline graph.

## What the CLI scores

The five OWASP Agentic 2026 risks with no direct web2 analogue:

| ID | Risk | Core danger |
|---|---|---|
| **ASI01** | Agent goal hijack | Injected instruction in a document, page, tool output, or email redirects downstream tool calls and plans |
| **ASI04** | Runtime supply chain | Tools, plugins, MCP servers, or sub-agents loaded at runtime may be poisoned or impersonated |
| **ASI06** | Memory poisoning | Malicious content written to session memory, RAG store, or long-term context, biasing future reasoning |
| **ASI09** | Fabricated rationale | Confident-sounding justification for a harmful action that causes a human approver to comply |
| **ASI10** | Rogue agent behavior | Goal drift, self-replication, or unintended coordination with other agents |

Verdict is one of:

- **PASS** — no Critical or High findings
- **REVIEW** — one or more High findings; modify before running
- **BLOCK** — one or more Critical findings; do not execute without significant redesign

## Step 0 — Locate `audit.py`

Look for the script in this order. Use the first hit.

```bash
# 1. Cached install in the user's home
~/clowasp/audit.py
# 2. Desktop / common project locations
~/Desktop/ai\ marketing\ automation/clowasp/audit.py
~/code/clowasp/audit.py
~/src/clowasp/audit.py
# 3. PATH
$(command -v clowasp-audit 2>/dev/null)
```

Run `find ~ -maxdepth 4 -name audit.py -path '*clowasp*' 2>/dev/null | head -3` if none of the above match. Cache the result in a shell variable for the rest of the session — do not re-search on every invocation.

If still not found, ask permission and install:

```bash
git clone https://github.com/aidan269/clowasp.git ~/clowasp
pip3 install --user rich openai anthropic
```

Confirm the install with `python3 ~/clowasp/audit.py --help`.

## Step 1 — Resolve the prompt to audit

`$ARGUMENTS` may be:

- **A quoted prompt string** (`"You are a research assistant…"`) → pass straight through
- **A file path** (`./system_prompt.md`, `agents.yaml`) → read the file. If it is YAML/JSON with multiple prompts (e.g. CrewAI `agents.yaml`), ask the user which agent's `goal` + `backstory` to audit, or audit each in sequence.
- **Empty** → ask the user to paste the prompt (multi-line OK; trim trailing whitespace)

Strip leading/trailing whitespace. Reject empty input with a clear error.

## Step 2 — Pick a provider

`audit.py` supports three backends. Default is `claude` (Claude Code CLI), but that can recurse or behave unpredictably when this skill is itself running inside Claude Code. Prefer external providers:

1. **`openai`** — if `OPENAI_API_KEY` is set in the environment. Default model `gpt-4o`.
2. **`anthropic`** — if `ANTHROPIC_API_KEY` is set. Default model `claude-sonnet-4-6`.
3. **`claude`** — only if neither key is present *and* the Claude Code CLI binary is on `PATH`. Note this in the output so the user knows the audit is being scored by the same engine they're running in.

If no provider is available, stop and instruct the user to set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

Let the user override with an explicit `--provider <name>` if they include it in `$ARGUMENTS`.

## Step 3 — Run the audit

```bash
python3 <audit-path> "<prompt>" \
  --provider <provider> \
  [--model <model>] \
  [--share] \
  [--json]
```

- `--share` opens a branded HTML card in the browser (`audit-card.html` next to `audit.py`). Offer this when the user says "share", "screenshot", "post this", or wants a deliverable.
- `--json` returns machine-readable output. Use this when chaining clowasp into another script.

For long prompts, write the prompt to a temp file and use `cat tmpfile | python3 audit.py --provider <provider>` to avoid shell quoting issues.

## Step 4 — Surface the result

The CLI prints a compact line (`🚫 BLOCK  openai / gpt-4o`) but the model output behind it contains the full structured report. Re-display it in this shape so the user sees the reasoning, not just the verdict:

```
## clowasp — [PASS / REVIEW / BLOCK]

**Workflow type:** [research / coding / copilot / multi-agent / general]
**Provider:** [openai / anthropic / claude]   **Model:** [model]

### Findings

For each of ASI01, ASI04, ASI06, ASI09, ASI10:

**[ASI0X — Risk label]** · Critical | High | Medium | Low | Not applicable
- Triggered by: [quote or element from the prompt]
- Attack path: [one sentence]
- Control: [mitigation]

### Safe rewrite

```
[The rewritten prompt — drop-in replacement keeping the same intent and capabilities but addressing every High/Critical finding. Always included, even on PASS.]
```

### Priority fixes

1. [Most urgent — one line]
2. [Second — one line]
3. [Third — one line]
```

If `--share` was requested, also print the path to `audit-card.html` and confirm it opened in the browser.

## Rules

- **Do not re-run the audit yourself.** The CLI is the source of truth. If `audit.py` returned `BLOCK`, do not soften it to `REVIEW` because the prompt looks polished.
- **Quote the user's exact prompt text** in the `Triggered by` field. Never paraphrase. The CLI already does this — preserve it.
- **Always include the safe rewrite**, even on `PASS` (the CLI is configured to emit one regardless).
- **Surface the model used.** Different providers produce different verdicts; the user needs to know which engine scored their prompt.
- **One audit per invocation.** If the user passes a `agents.yaml` with five agents, ask which one — don't run five audits in parallel without consent.
- **Do not edit the user's source files** unless explicitly asked. Print the safe rewrite; let the user paste it where it belongs.

## Related skills and commands

- `/cantinasec:inject` — focused ASI01 sub-audit for prompt-injection surfaces in a pipeline
- `/cantinasec:tripwire` — broader OWASP Agentic 2026 audit against a pipeline graph
- `/cantinasec:clawtsuite` — audits installed Claude skills (not prompts) against Cantina's 6-point standard

Source: https://github.com/aidan269/clowasp · eval suite: 10/10 passing against the OWASP benchmark.
