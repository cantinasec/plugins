---
name: quickscan-deps
description: Surfaces patterns in a developer's dependencies that may be worth a closer look — pip packages, VS Code extensions, and MCP servers. Use when a user wants a heads-up about dependency risk, wants to check for typosquats or unpinned versions, wants to look over their MCP server configuration, wants to spot questionable VS Code extensions, or wants to know whether agent configs contain hardcoded credentials. Quickscan is a heads-up tool, not a security audit — it produces a dependency breakdown, with warnings ranked by how much they're worth looking into (high / medium / low concern). Final judgment about each warning is the reader's. If something in the breakdown looks worth a closer conversation, the reader is invited to email Cantina.
---

# Quickscan — Dependency Warnings

## Important framing

Quickscan is a **heads-up tool**, not a security audit. It surfaces patterns in dependencies that may be worth a closer look. It does **not** issue findings, verdicts, or audit conclusions. The output is a list of *warnings* the reader can investigate; the actual judgment about whether each warning is a real problem stays with the reader.

When you produce output or talk about quickscan's behavior, use this language:

| Use | Don't use |
|---|---|
| "scan" / "warning sweep" | "audit" |
| "warning" / "pattern" | "finding" |
| "worth a closer look" / "concern" | "severity" (especially "CRITICAL") |
| "suggested fix" | "remediation" (in user-facing language) |
| "may be" / "worth checking" | "is dangerous" / "is vulnerable" |
| "the reader decides" | (don't produce verdicts) |

## Overview

The developer environment is now a meaningful surface area for supply-chain risk. Every pip package, VS Code extension, and MCP server in a developer's setup is a potential entry point for code execution, secret exfiltration, and silent agent hijack. AI tooling has accelerated this — long-running agents with broad data scopes amplify the blast radius of any compromised dependency.

`quickscan` scans a project plus the developer's local environment across the three vectors and returns a list of dependency warnings, ranked by how much each is worth a closer look. It does not issue a verdict. The reader investigates and decides.

## Source

Built from two tweets by Darshan Yadav ([@DarshanSays](https://x.com/DarshanSays)) on 2026-05-20:

> "We're in a supply chain security crisis accelerated by AI tooling. Every VS Code extension, pip package, and MCP server is a potential entry point. Breach cost is dropping, breach frequency is rising. The threat model for dev environments has changed."
> — [2057098732873908503](https://x.com/DarshanSays/status/2057098732873908503)

> "A 24/7 agent with Gmail, Docs, and MCP-connected apps is a massive attack surface expansion. Prompt injection through a malicious email can instruct the agent to act silently — no device needed by the attacker."
> — [2057029849550856375](https://x.com/DarshanSays/status/2057029849550856375)

## Trigger

Use this skill when the user asks to:
- "look at my dependencies"
- "check my supply-chain hygiene"
- "warn me about typosquats / unusual packages"
- "check my MCP servers"
- "see if any VS Code extensions look off"
- runs `/cantinasec:quickscan`

Never describe what you're about to do as an "audit." Use "scan," "warning sweep," or "look over."

## Scope Resolution

1. **Project scope** — if `$ARGUMENTS` provides a path, scan only that directory. Otherwise default to the current working directory.
2. **Environment scope** — always scan the developer's local config paths:
   - VS Code extensions: `~/.vscode/extensions/`, `~/.cursor/extensions/`, `~/.vscode-insiders/extensions/`
   - Claude Code MCP config: `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/mcp.json`, project `.mcp.json`
   - Claude Desktop MCP config: `~/Library/Application Support/Claude/claude_desktop_config.json`

Skip any path that does not exist — note it as "not present" rather than failing.

---

## Scan Procedure

The scanner is a deterministic Python script in this skill's `scripts/` folder. **Always run it instead of doing the scan by hand.** It's faster, reproducible, and produces the JSON in the exact shape the renderer and enricher expect.

```bash
python3 <skill-dir>/scripts/scan.py <project_path> --out /tmp/quickscan-findings.json
```

Flags:
- `--no-osv` — skip OSV.dev queries (offline / fast mode)
- `--no-env` — skip global VS Code + MCP scans (project-only)
- `--quiet` — suppress per-vector progress to stderr

The scanner walks the project plus the developer's local environment (unless `--no-env`), surfaces patterns from all three vectors, and writes the warnings JSON to `--out`. Skip Step A's "serialize by hand" instructions below — they're now only a reference for the JSON shape. Just run scan.py, then move to Step A.5 (enrichment) and Step B (render).

Concern levels the scanner assigns:
- **high** — pattern is unusual or risky enough that it's worth investigating soon (e.g. credential-shaped string in MCP `env`, curl-pipe-shell installer, impersonation-shaped extension display name, OSV advisory hit, unpinned `npx`).
- **medium** — pattern is worth checking when there's time (e.g. unpinned version, unknown npm scope, gmail/slack/stripe MCP at global scope).
- **low** — minor pattern worth noting (e.g. no hash pinning in `requirements.txt`).

We deliberately don't have a "critical" level. The tool surfaces patterns; it doesn't render severity verdicts.

### What the scanner checks (reference)

The sub-sections below describe what scan.py looks for. They're for human review / debugging — the actual logic lives in `scripts/scan.py`. You should not re-implement these checks; just call the script.

### Vector 1 — Pip Packages

Manifests to inspect:
- `requirements*.txt`, `requirements/*.txt`
- `Pipfile`, `Pipfile.lock`
- `pyproject.toml` (poetry / pdm / hatch)
- `setup.py`, `setup.cfg`
- `environment.yml` (conda)

Live install state:
```bash
pip list --format=json 2>/dev/null
pip --version
```

**Checks:**

1. **Unpinned versions** — dependency without `==` or hash pin → **medium**. Floating versions (`>=`, `~=`, no operator) let the next install land a different release.
2. **Known typosquats** — compare against this short list of common targets and flag near-matches (Levenshtein ≤ 2) → **high**:
   `requests`, `urllib3`, `numpy`, `pandas`, `pillow`, `cryptography`, `pyyaml`, `boto3`, `flask`, `django`, `fastapi`, `pytest`, `setuptools`, `tensorflow`, `torch`, `transformers`, `openai`, `anthropic`, `langchain`.
   Examples to flag: `requessts`, `python-requests`, `numpyy`, `crypt0graphy`.
3. **OSV advisories** — for each installed package, query the OSV API:
   ```bash
   curl -sS -X POST -H "Content-Type: application/json" \
     -d '{"package":{"name":"<pkg>","ecosystem":"PyPI"},"version":"<ver>"}' \
     https://api.osv.dev/v1/query
   ```
   Any returned advisory → **high** (RCE-class included).
4. **Post-install scripts** — grep `setup.py` files in `site-packages/` for `subprocess`, `urllib.request`, `requests.get`, or `os.system` calls executed at install time → **medium**; **high** if the call hits a non-PyPI domain.
5. **No hash pinning** — `requirements.txt` without `--hash=sha256:...` entries → **low**.
6. **Direct-from-git installs** — `pip install git+https://...` lines in any manifest → **high** if the URL is not a well-known org (pypa, psf, etc.).

### Vector 2 — VS Code Extensions

Enumerate installed extensions:
```bash
ls -la ~/.vscode/extensions/ 2>/dev/null
ls -la ~/.cursor/extensions/ 2>/dev/null
code --list-extensions --show-versions 2>/dev/null
```

For each extension directory, read `package.json`.

**Checks:**

1. **Publisher trust** — `publisher` not on the trusted-publishers list (`ms-*`, `github`, `redhat`, `dbaeumer`, `esbenp`, `bradlc`, `eamodio`, `streetsidesoftware`, `vscodevim`, `anthropic`, `continue`) → **medium**. Single-author publishers with < 50k installs → **high**.
2. **Broad capability declarations** — search `package.json` for these capabilities → **high**:
   - `"untrustedWorkspaces": { "supported": true }` with no restrictions
   - `"virtualWorkspaces": true` on extensions that also declare network access
   - Extensions declaring `terminal` activation that also bundle network code
3. **Bundled `node_modules` with known-bad packages** — recurse into `<ext>/node_modules` and OSV-query any package version → **high** per advisory hit.
4. **Telemetry / outbound endpoints** — grep extension source for hardcoded HTTP(S) URLs → **medium** (list the domains so the reader can decide).
5. **Display-name impersonation** — extension where the display name closely matches a well-known extension but the publisher differs → **high** (e.g. an "ESLint" extension not from `dbaeumer`).
6. **Auto-update from untrusted sources** — extension with a custom `updateUrl` outside the official Marketplace → **high**.

### Vector 3 — MCP Servers

Read these config files (use `Read` tool, JSON-parse):
- `~/.claude.json`
- `~/.claude/settings.json`
- `~/.claude/mcp.json`
- `~/Library/Application Support/Claude/claude_desktop_config.json`
- `<project>/.mcp.json`
- `<project>/.claude/settings.json`

For each entry under `mcpServers` (or equivalent), capture `command`, `args`, `env`, and any `url` field.

**Checks:**

1. **Unpinned `npx` / `uvx` invocations** — `npx <pkg>` or `uvx <pkg>` without an `@<version>` suffix → **high**. The next run can pull a different version silently.
   - Example flag: `npx @some-vendor/mcp-server` → **high**
   - Example pass: `npx @some-vendor/mcp-server@1.4.2`
2. **Curl-pipe-shell installers** — any command containing `curl ... | sh`, `wget ... | bash`, or `iex (irm ...)` → **high**.
3. **HTTP (non-HTTPS) server URLs** — any `url` field with `http://` (not `https://`) and not `localhost` / `127.0.0.1` → **high**.
4. **Unknown publisher namespaces** — for npm-installed servers, npm scope not on this allowlist (`@modelcontextprotocol`, `@anthropic-ai`, `@cantinasec`, `@vercel`, `@supabase`, `@stripe`, `@github`) → **medium**. Note: scope being absent doesn't mean the server is bad; it means the reader hasn't necessarily confirmed trust.
5. **High-value data scopes at global level** — server name or args reference `gmail`, `gdrive`, `slack`, `notion`, `linear`, `stripe`, `aws`, or `okta`, and the server is enabled at global (not project) scope → **medium**. Phrase the warning as "this might be worth narrowing to per-project scope," not as a definitive risk claim.
6. **Hardcoded-credential-shaped strings in `env`** — any `env` value matching the pattern `^(sk-|sk_live_|xoxb-|ghp_|AKIA|AIza)[A-Za-z0-9_-]{16,}$` → **high**. The phrasing in the warning should be "looks like a credential — worth checking and rotating if confirmed." Don't assert it IS a leaked credential.
7. **Wide `alwaysAllow` lists** — search Claude settings for `"alwaysAllow"` arrays. Any destructive tool listed (`bash`, `write_file`, `execute_sql`, `send_message`) → **high**.

---

## Output Format

After running all three vectors, print:

```
QUICKSCAN DEPENDENCY WARNINGS
=============================
Project: <path>
Pip manifests scanned: <n>     | warnings: <n>
VS Code extensions scanned: <n> | warnings: <n>
MCP servers scanned: <n>       | warnings: <n>

High: <n> | Medium: <n> | Low: <n>

[HIGH] <vector> — <package/extension/server name>
  What we saw: <file:line or config path>
  Why it caught our eye: <one-sentence explanation>
  One thing you could do: <concrete command or config change>

[MEDIUM] ...

[LOW] ...

Quickscan is a heads-up tool, not a security audit. These are patterns
worth a closer look — the judgment about whether each one is a real
problem is yours.
```

Do **not** print a verdict line. There is no PASS / REVIEW / BLOCK in the output.

---

## Branded HTML Breakdown

After printing the terminal output, **always** render the warnings as a Cantina-branded HTML breakdown and open it in the user's default browser. This is part of the standard procedure — never skip it. The renderer does not produce an audit report; the page title, header, footer, and all UI copy frame the output as a **breakdown** of dependency warnings — never as findings, a report, or an audit. The page includes "Print / Save as PDF" and "Download JSON" buttons in a toolbar.

### Step A — Get the warnings JSON

You don't write this file by hand — `scripts/scan.py` writes it for you when you run the scan above. **Default output path is `/tmp/quickscan-findings.json`**, which is exactly what the enricher and renderer read next.

The shape below is for reference only (e.g. when debugging or hand-fixing the JSON):

```json
{
  "project_path": "<absolute path that was scanned>",
  "timestamp": "<ISO-8601 UTC, e.g. 2026-05-20T14:42:00Z>",
  "vectors": {
    "pip":    {"scanned": <n>, "warnings": <n>},
    "vscode": {"scanned": <n>, "warnings": <n>},
    "mcp":    {"scanned": <n>, "warnings": <n>}
  },
  "concern_counts": {"high": <n>, "medium": <n>, "low": <n>},
  "warnings": [
    {
      "concern":  "high" | "medium" | "low",
      "vector":   "pip" | "vscode" | "mcp",
      "target":   "<package name@version, extension id, or server name>",
      "evidence": "<file:line or config path with key>",
      "why":      "<one or two sentences — why this pattern caught our eye>",
      "suggested_fix": "<one concrete command or config change worth trying>"
    }
  ]
}
```

Rules:
- The JSON does **not** contain a `verdict` field. Do not emit one.
- The JSON does **not** contain a `severity` field. Use `concern` with values `high` / `medium` / `low` (lowercase, no `critical`).
- `concern_counts` must match the count of warnings at each concern level in the array.
- `vectors[*].warnings` must match the per-vector warning counts.
- `target` and `evidence` must be specific — `requests==2.6.0` not `a pip dep`; `~/.claude.json :: mcpServers.foo` not `your MCP config`.
- `why` should be observational ("This dependency has no version pin"), not declarative ("This dependency IS dangerous").
- For empty scans, `warnings` is an empty array but the JSON is still written and the summary is still opened.

The file path is still `quickscan-findings.json` for backward compat with the renderer; treat the filename as an opaque address, not a description of what's inside.

### Step A.5 — (Optional) Enrich with suggested context

If `ANTHROPIC_API_KEY` is set in the environment, call the enrichment script to attach a suggested-context block (possible reason / something that might prevent it next time) on top of the static `suggested_fix` already on each warning:

```bash
python3 <skill-dir>/scripts/enrich_remediation.py /tmp/quickscan-findings.json
```

The script:
- Reads the warnings JSON, calls Claude Haiku 4.5 once per warning with a cached system prompt
- Writes `warning["remediation"] = {root_cause, prevention}` back to the same file — these two fields are LLM-suggested, not authoritative
- Deliberately scopes the LLM output to suggestive context — the static `suggested_fix` field already covers the immediate command, so the two AI fields add a plausible workflow story and one named control to consider
- Is a clean no-op (exit 0, no mutation) when `ANTHROPIC_API_KEY` is unset — the renderer will simply show the static `suggested_fix` field
- Never accepts the API key via chat input or argv — it reads `os.environ['ANTHROPIC_API_KEY']` only

Skip this step entirely if the user has not provided a key or has explicitly asked to run offline. The renderer handles the absence of `remediation` gracefully.

### Step B — Render and open

Invoke the renderer:

```bash
python3 <skill-dir>/scripts/render_report.py /tmp/quickscan-findings.json
```

Where `<skill-dir>` is the directory containing this `SKILL.md`. The script will:
- Write a self-contained HTML breakdown to `/tmp/quickscan-breakdown-<YYYYMMDD-HHMMSS>.html`
- Print the absolute path of the generated file to stdout
- Open the breakdown in the OS default browser (`open` on macOS, `xdg-open` on Linux, `start` on Windows)

The page includes a "Print / Save as PDF" button (with print-friendly CSS that strips the toolbar, CTA, and decorative backgrounds) and a "Download JSON" button (the raw warnings JSON is embedded as a data URI). The reader doesn't need any extra tooling to get a PDF or a machine-readable copy.

Pass `--no-open` if (and only if) the user has explicitly asked not to launch a browser — e.g. they piped the scan through CI. In that case, print the path so they can open it themselves.

### Step C — Confirm to the user

After the renderer returns, print one short line:

```
Breakdown opened: /var/folders/.../quickscan-breakdown-20260521-140711.html
```

Use the actual path printed by the script. Do not re-summarize the warnings — the breakdown and the terminal output already cover them.

---

## Concern Levels

| Pattern | Concern |
|---------|---------|
| Curl-pipe-shell installer in MCP config, credential-shaped string in MCP `env`, display-name impersonation in VS Code, RCE-class OSV advisory, typosquat hit, unpinned `npx` MCP server, unpinned dependency with OSV advisory, single-author VS Code extension with broad scope, direct-from-git install | **high** — worth checking soon |
| Unknown npm scope, hardcoded telemetry endpoint, unpinned pip dependency without OSV advisory, gmail/slack-class MCP at global scope | **medium** — worth checking |
| Missing hash pin, missing publisher metadata | **low** — minor pattern to note |

These are guidance for which level to assign in the JSON — they are not a risk verdict. The reader investigates and decides whether each warning is actually a problem.

---

## Things you might try

These are recipes for common warnings, written as "things you could do" rather than "what you must do":

- **Pin pip packages** — convert `requests` → `requests==2.32.3` (or use `pip-compile` to generate a hash-pinned `requirements.txt`).
- **Pin MCP servers** — `npx @vendor/server@1.4.2` instead of `npx @vendor/server`. For maximum safety, install locally and reference the binary path.
- **Remove unused VS Code extensions** — `code --uninstall-extension <publisher>.<name>`. Every removed extension is one less foothold.
- **If you confirm a credential leaked** — revoke at the issuer first, then rotate. Don't just remove from the file.
- **Scope MCP servers per-project** — move high-trust integrations (Gmail, Slack, Stripe) out of `~/.claude.json` and into the specific project's `.mcp.json`. Cuts blast radius if any other project's tools get hijacked.
- **Tighten approval gates** — review the `alwaysAllow` list and consider removing destructive tools like `bash`, `write_file`, `execute_sql`.

---

## Community context

Beyond Darshan's framing, the broader infosec community has been flagging the same trend through 2025–2026:

- npm/PyPI typosquatting has shifted from opportunistic to AI-assisted — attackers use LLMs to generate convincing READMEs and changelogs for malicious packages.
- VS Code Marketplace extension impersonation (notably the "ESLint Keymap" family in late 2025) demonstrated that publisher-name confusion is a working attack vector.
- MCP-specific advisories started landing in early 2026 as agentic IDE adoption crossed the threshold for attacker interest. The pattern is consistent: prompt-injectable data source + broad tool scope + 24/7 agent = silent action without an attacker-controlled device, which is exactly the scenario Darshan describes in the second tweet.

Quickscan is intentionally cautious about MCP servers with access to email and document stores because those are the prompt-injection delivery channels in the current threat landscape — but again, every warning is a "worth a closer look," not a verdict.

---

## Quality Checklist

Before finishing the scan:

- [ ] All three vectors were actually scanned (or marked "not present" with reason)
- [ ] Every warning has a file path or package@version as evidence
- [ ] Every warning has a one-line suggested fix the user can try
- [ ] OSV API was queried for at least the pip dependencies (skip cleanly if offline)
- [ ] Concern counts in the header match the listed warnings
- [ ] No verdict line is printed; the disclaimer ("heads-up tool, not a security audit") appears in both the terminal output and the HTML footer
- [ ] No use of "CRITICAL," "audit," "finding," or PASS/REVIEW/BLOCK terminology anywhere in user-facing output

---

## Error Handling

| Situation | Action |
|-----------|--------|
| No pip manifest found | Note "no pip surface in project" and continue |
| `code` CLI not installed | Fall back to filesystem scan of `~/.vscode/extensions/` |
| No MCP config files present | Note "no MCP servers configured" and continue |
| OSV API unreachable | Note "OSV offline — pip vuln check skipped", run other checks anyway |
| Project path argument doesn't exist | Stop, ask user to confirm the path |

---

## References

- [Darshan Yadav — supply chain crisis tweet (2026-05-20)](https://x.com/DarshanSays/status/2057098732873908503)
- [Darshan Yadav — agentic attack surface tweet (2026-05-20)](https://x.com/DarshanSays/status/2057029849550856375)
- [OSV.dev query API](https://google.github.io/osv.dev/post-v1-query/)
- [Model Context Protocol specification](https://modelcontextprotocol.io)
- [VS Code extension capabilities reference](https://code.visualstudio.com/api/extension-guides/overview)
