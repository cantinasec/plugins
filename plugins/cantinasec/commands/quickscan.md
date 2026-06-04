---
description: Surface dependency warnings across pip packages, VS Code extensions, and MCP servers — a heads-up, not an audit
allowed-tools: Bash, Grep, Glob, Read
---

Run the `quickscan-deps` skill to scan this project and the developer's local environment for dependency patterns worth a closer look across the three vectors Darshan Yadav called out: pip packages, VS Code extensions, and MCP servers. Output a list of warnings ranked by concern (high / medium / low) with a suggested fix for each. Do not issue an audit verdict — quickscan is a heads-up tool.

If `$ARGUMENTS` provides a path, scope the project scan to that directory. Otherwise scan the current working directory plus the user's global VS Code and MCP configs.

$ARGUMENTS
