---
description: Audit an AI agent pipeline against the OWASP Agentic Top 10 2026 and return PASS / REVIEW / BLOCK with drop-in remediations
allowed-tools: Bash, Grep, Glob, Read
---

Run the `clowasp` skill to audit an AI agent pipeline against the OWASP Top 10 for Agentic Applications 2026. The skill reconstructs the pipeline topology, scores every agent and connection against all ten risks (ASI01–ASI10), and returns a single verdict — **PASS**, **REVIEW**, or **BLOCK** — alongside drop-in YAML / prompt fixes for each finding.

Pass a file path, an exported workflow (CrewAI, n8n, LangGraph, AutoGen, Flowise), a Python snippet, or a plain-text description. If no argument is provided, the skill auto-discovers pipeline files in the current directory.

$ARGUMENTS
