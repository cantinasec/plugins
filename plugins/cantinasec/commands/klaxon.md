---
description: Set up and demo klaxon - Cantina's self-hosted social monitoring and brand protection tool
allowed-tools: Bash, Grep, Glob, Read, Edit, Write
---

Run the `klaxon-setup` skill to clone, install, configure, and demo klaxon — a self-hosted alternative to ZeroFox Social Media Protection and Akamai Brand Guardian, focused on awareness and alerting (never automated remediation).

The skill walks the user through: clone → install → fill the YAML config interactively (organization, brand, executives, keywords) → optional Slack wiring → the two-pane drip demo that fires fixture findings into a local webhook receiver instead of touching real Slack.

$ARGUMENTS
