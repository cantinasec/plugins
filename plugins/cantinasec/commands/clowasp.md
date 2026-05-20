---
description: Audit an LLM/agent prompt against the OWASP Agentic Top 10 2026 (five net-new risks) and return PASS / REVIEW / BLOCK with a safe rewrite
allowed-tools: Bash, Grep, Glob, Read, Edit, Write
---

Run the `clowasp` skill to audit an LLM or agent prompt — system prompt, tool description, MCP config, or agent instruction — against the **OWASP Top 10 for Agentic Applications 2026**, scoring the five net-new risks (ASI01 goal hijack, ASI04 supply chain, ASI06 memory poisoning, ASI09 fabricated rationale, ASI10 rogue agents) and returning a single verdict — **PASS**, **REVIEW**, or **BLOCK** — alongside a drop-in safe rewrite of the original prompt.

The skill drives the `audit.py` CLI from [aidan269/clowasp](https://github.com/aidan269/clowasp): clones the repo on first run, picks a provider (`openai` / `anthropic` / Claude Code CLI) based on which keys are available, and renders the share-card HTML when asked.

Pass the prompt to audit as `$ARGUMENTS` (quote it), a file path containing the prompt, or invoke with no arguments to be prompted interactively.

$ARGUMENTS
