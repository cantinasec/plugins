# plugins

Cantina Claude Marketplace Plugins

## Install

```
/plugin marketplace add cantinasec/plugins
/plugin install cantinasec@cantinasec-plugins
/reload-plugins
```

## Commands

- `/cantinasec:axios` — Check for the axios npm supply-chain compromise (versions 1.14.1, 0.30.4)
- `/cantinasec:litellm` — Check for the litellm PyPI supply-chain compromise (versions 1.82.7, 1.82.8)
- `/cantinasec:klaxon` — Set up and demo klaxon, Cantina's self-hosted social monitoring and brand-protection tool (impersonation, mention spikes, keyword spikes)
- `/cantinasec:clowasp` — Audit an AI agent pipeline (CrewAI, n8n, LangGraph, AutoGen, Flowise) against the OWASP Agentic Top 10 2026 and return PASS / REVIEW / BLOCK with drop-in fixes
