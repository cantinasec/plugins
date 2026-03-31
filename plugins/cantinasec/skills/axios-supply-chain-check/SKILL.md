---
name: axios-supply-chain-check
description: Check whether a project or environment was affected by the compromised axios npm package versions (1.14.1, 0.30.4)
---

# Axios Supply-Chain Compromise Check

## Background

On 2026-03-31, malicious versions of the `axios` npm package were published:

- **axios@1.14.1** (tagged `latest`) — added `plain-crypto-js@4.2.0` as a dependency with a malicious `postinstall` script.
- **axios@0.30.4** (tagged `legacy`) — same payload via `plain-crypto-js@4.2.1`.

The compromised npm account was `jasonsaayman` (email changed to `ifstap@proton.me`). Safe versions are **1.14.0** and **0.30.3** respectively.

The malicious dependency `plain-crypto-js` contains a `setup.js` postinstall script that uses two-layer obfuscation (string reversal + base64, then XOR with key `"OrDeR_7077"`). It downloads and executes platform-specific stage-2 payloads from the C2 server `sfrclak.com:8000` with campaign ID `6202033`.

**Platform-specific behavior:**

- **macOS:** Deploys AppleScript via `osascript` to download a binary to `/Library/Caches/com.apple.act.mond`
- **Windows:** Copies PowerShell to `%PROGRAMDATA%\wt.exe`, drops a VBScript wrapper at `%TEMP%\6202033.vbs` and a script at `%TEMP%\6202033.ps1` with `-ep bypass`
- **Linux:** Downloads a Python script to `/tmp/ld.py` via `curl`, executes with `nohup`

The payload self-deletes and overwrites `package.json` to evade forensic analysis.

## When to Use

Run this skill when the user wants to check whether a project, environment, host, or CI pipeline was affected by the compromised axios npm package versions.

## Procedure

When invoked, run ALL of the following checks. Present results in a structured report at the end.

### 1. Check installed axios and plain-crypto-js versions

```bash
echo "=== Global npm ==="
npm ls -g axios 2>/dev/null || echo "axios not installed globally"
echo ""
npm ls -g plain-crypto-js 2>/dev/null || echo "plain-crypto-js not installed globally"

echo ""
echo "=== Project node_modules ==="
if [ -d "node_modules" ]; then
  echo "--- axios ---"
  node -e "try { console.log('Version:', require('axios/package.json').version) } catch(e) { console.log('axios not installed in project') }"
  echo "--- plain-crypto-js ---"
  node -e "try { console.log('Version:', require('plain-crypto-js/package.json').version) } catch(e) { console.log('plain-crypto-js not installed in project') }"
else
  echo "No node_modules directory found"
fi

echo ""
echo "=== pnpm ==="
pnpm ls axios 2>/dev/null || echo "pnpm not available or axios not installed"

echo ""
echo "=== yarn ==="
yarn info axios version 2>/dev/null || echo "yarn not available or axios not installed"

echo ""
echo "=== bun ==="
bun pm ls 2>/dev/null | grep -E "axios|plain-crypto-js" || echo "bun not available or packages not installed"
```

### 2. Check lockfiles for compromised versions

Use the Grep tool (NOT bash grep) to search the project directory. Run these in parallel:

1. **package-lock.json** — search for pattern `1\.14\.1|0\.30\.4|plain-crypto-js` with glob `**/package-lock.json` (output_mode: content)
2. **yarn.lock** — search for pattern `1\.14\.1|0\.30\.4|plain-crypto-js` with glob `**/yarn.lock` (output_mode: content)
3. **pnpm-lock.yaml** — search for pattern `1\.14\.1|0\.30\.4|plain-crypto-js` with glob `**/pnpm-lock.yaml` (output_mode: content)
4. **bun.lockb / bun.lock** — search for pattern `1\.14\.1|0\.30\.4|plain-crypto-js` with glob `**/bun.lock*` (output_mode: content)
5. **package.json** — search for pattern `axios|plain-crypto-js` with glob `**/package.json` (output_mode: content)

**Risk classification for each match:**
- Contains `1.14.1`, `0.30.4`, or `plain-crypto-js` → **HIGH RISK**
- Contains `axios` with no version pin (e.g. `"axios": "*"` or `"axios": "latest"`) → **MEDIUM RISK**
- Contains `axios` pinned to a version outside 1.14.1/0.30.4 → **LOW RISK**

**IMPORTANT:** Exclude matches inside `~/.claude/skills/` — those are this skill's own instructions, not project references.

### 3. Search for the malicious plain-crypto-js package and setup.js

```bash
echo "=== Searching for plain-crypto-js in node_modules ==="
find . -maxdepth 5 -path "*/plain-crypto-js/package.json" -type f 2>/dev/null || echo "plain-crypto-js not found in project"

echo ""
echo "=== Searching for setup.js postinstall script ==="
find . -maxdepth 5 -path "*/plain-crypto-js/setup.js" -type f 2>/dev/null || echo "setup.js not found"

echo ""
echo "=== Checking for XOR key in any JS files under node_modules ==="
grep -rl "OrDeR_7077" node_modules/ 2>/dev/null | head -10 || echo "XOR key 'OrDeR_7077' not found in node_modules"
```

### 4. Search for stage-2 payload artifacts (platform IOCs)

```bash
echo "=== macOS IOC ==="
if [ -f "/Library/Caches/com.apple.act.mond" ]; then
  echo "FOUND: /Library/Caches/com.apple.act.mond"
  ls -la "/Library/Caches/com.apple.act.mond"
  file "/Library/Caches/com.apple.act.mond"
else
  echo "/Library/Caches/com.apple.act.mond NOT found"
fi

echo ""
echo "=== Windows IOCs (WSL/cross-check) ==="
for f in \
  "${PROGRAMDATA}/wt.exe" \
  "${TEMP}/6202033.vbs" \
  "${TEMP}/6202033.ps1"; do
  if [ -n "$f" ] && [ -f "$f" ]; then
    echo "FOUND: $f"
  fi
done
echo "(Windows IOC check done)"

echo ""
echo "=== Linux IOC ==="
if [ -f "/tmp/ld.py" ]; then
  echo "FOUND: /tmp/ld.py"
  ls -la "/tmp/ld.py"
  head -5 "/tmp/ld.py"
else
  echo "/tmp/ld.py NOT found"
fi
```

### 5. Check for C2 domain in logs, source, and history

Use the Grep tool for project files and bash for system-level checks. Run in parallel:

**Grep tool call:** search the project directory for pattern `sfrclak\.com|6202033` (output_mode: content). Exclude files under `~/.claude/skills/`.

**Bash call:**

```bash
echo "=== Shell history ==="
grep -n "sfrclak\.com\|6202033" ~/.bash_history ~/.zsh_history 2>/dev/null || echo "No C2 IOC found in shell history"

echo ""
echo "=== DNS cache (macOS) ==="
if command -v dscacheutil &>/dev/null; then
  dscacheutil -cachedump 2>/dev/null | grep -i "sfrclak" || echo "sfrclak.com not in DNS cache (or cachedump unavailable)"
fi

echo ""
echo "=== System logs (best effort, 10s timeout) ==="
timeout 10 grep -rln "sfrclak\.com\|6202033" /var/log/ 2>/dev/null || echo "No C2 IOC found in /var/log (or not accessible)"

echo ""
echo "=== Network connections (live check) ==="
if command -v lsof &>/dev/null; then
  lsof -i -nP 2>/dev/null | grep -i "sfrclak\|8000" | head -10 || echo "No active connections to C2"
elif command -v ss &>/dev/null; then
  ss -tunap 2>/dev/null | grep "8000" | head -10 || echo "No active connections to C2"
fi
```

**IMPORTANT:** If Grep matches files inside `~/.claude/skills/`, discard those — they are this skill file, not real IOCs.

### 6. Check for signs of postinstall execution and self-cleanup

```bash
echo "=== npm cache ==="
npm cache ls 2>/dev/null | grep -E "axios|plain-crypto-js" | head -20 || echo "npm cache command unavailable or no matches"

echo ""
echo "=== npm log files ==="
find ~/.npm/_logs/ -name "*.log" -newer /dev/null -mtime -7 2>/dev/null | while read logfile; do
  grep -l "plain-crypto-js\|setup\.js\|postinstall" "$logfile" 2>/dev/null
done || echo "No recent npm logs with IOCs"

echo ""
echo "=== Check for overwritten package.json (modification time anomaly) ==="
if [ -f "node_modules/axios/package.json" ]; then
  echo "axios package.json last modified:"
  stat -f "%Sm" "node_modules/axios/package.json" 2>/dev/null || stat -c "%y" "node_modules/axios/package.json" 2>/dev/null
  echo ""
  echo "Checking if plain-crypto-js is still listed as dependency:"
  node -e "const p = require('./node_modules/axios/package.json'); console.log('dependencies:', JSON.stringify(p.dependencies || {}, null, 2))" 2>/dev/null
fi
```

### 7. Check CI/CD configurations and Dockerfiles

Use the Grep tool (NOT bash grep). Run these in parallel:

1. **CI configs** — search for pattern `axios|plain-crypto-js` with glob `*.{yml,yaml}` (case-insensitive, output_mode: content)
2. **Dockerfiles** — search for pattern `axios|plain-crypto-js` with glob `Dockerfile*` (case-insensitive, output_mode: content)
3. **GitHub Actions** — search for pattern `axios|plain-crypto-js` with glob `.github/**/*.{yml,yaml}` (case-insensitive, output_mode: content)

**IMPORTANT:** Exclude matches inside `~/.claude/skills/`.

### 8. Check shell history for install commands

```bash
grep -n "npm.*install.*axios\|yarn.*add.*axios\|pnpm.*add.*axios\|bun.*add.*axios\|plain-crypto-js" ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null || echo "No axios install found in shell history"
```

## Report Format

After running all checks, present a structured report:

```
## Axios Supply-Chain Check Report

**Project:** <project path>
**Date:** <current date>
**Exposure Level:** HIGH / MEDIUM / LOW / NONE

### Findings

| Check                              | Result   | Details                    |
|------------------------------------|----------|----------------------------|
| Installed axios version            | ...      | ...                        |
| Installed plain-crypto-js          | YES / NO | version if found           |
| Lockfile references                | YES / NO | files and versions found   |
| plain-crypto-js in node_modules    | YES / NO | path if found              |
| XOR key (OrDeR_7077) found         | YES / NO | files if found             |
| Stage-2 payload artifacts          | YES / NO | paths if found             |
| C2 domain (sfrclak.com) in logs    | YES / NO | locations if found         |
| Campaign ID (6202033) in files     | YES / NO | locations if found         |
| npm cache / log IOCs               | YES / NO | details                    |
| CI/CD references                   | YES / NO | files and risk level       |
| Docker references                  | YES / NO | files and risk level       |
| Shell history                      | YES / NO | relevant commands          |

### Exposure Assessment

- **HIGH**: axios 1.14.1 or 0.30.4 installed, or plain-crypto-js found, or stage-2 artifacts found, or C2 domain contacted
- **MEDIUM**: Unpinned axios install found in manifests/CI during incident window (2026-03-31 onward)
- **LOW**: axios referenced but pinned to safe version
- **NONE**: No axios references found, or pinned to safe version with clean lockfile

### Recommended Actions

If HIGH:
1. **Immediately** isolate affected systems from the network
2. Rotate ALL credentials, tokens, and secrets accessible on affected systems
3. Remove compromised packages: `npm uninstall axios plain-crypto-js && npm cache clean --force`
4. Delete stage-2 artifacts:
   - macOS: `rm -f /Library/Caches/com.apple.act.mond`
   - Linux: `rm -f /tmp/ld.py`
   - Windows: delete `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
5. Block `sfrclak.com` at network perimeter / DNS
6. Rebuild affected environments from clean base images
7. Pin to safe version: `npm install axios@1.14.0`
8. Review outbound network logs for connections to `sfrclak.com:8000`
9. Notify security team and consider incident response

If MEDIUM:
1. Verify lockfile pins to safe versions
2. Run `npm audit` and regenerate lockfile
3. Consider credential rotation as a precaution
4. Pin axios to a known safe version

If LOW:
1. Verify pinned version is not in the compromised range
2. Ensure lockfile is committed and `npm ci` is used in CI (not `npm install`)

If NONE:
1. No action required for this project
```

## Important Notes

- Do NOT skip any check even if early results look clean
- The `postinstall` script executes immediately on `npm install` — no code import needed
- The payload self-deletes and overwrites `package.json` to cover its tracks, so absence of `plain-crypto-js` in the current `package.json` does not mean the system was never exposed
- Even if the package is now uninstalled, historical exposure still matters — rotate credentials
- A clean current state does not mean the system was never exposed — check history and artifacts
- All bash commands use timeouts or scoped paths to avoid hanging
- Discard any Grep/search matches inside `~/.claude/skills/` — those are this skill file, not real IOCs
- The compromised account `jasonsaayman` had its email changed to `ifstap@proton.me` — this is an indicator of account takeover
