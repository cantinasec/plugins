---
name: litellm-supply-chain-check
description: Check whether a project or environment was affected by the compromised litellm PyPI package versions (1.82.7, 1.82.8)
---

# LiteLLM Supply-Chain Compromise Check

## Background

On 2026-03-24, malicious versions of the `litellm` package were published to PyPI:

- **1.82.7** — payload in `litellm/proxy/proxy_server.py`; activates when that module is imported.
- **1.82.8** — same payload **plus** a `litellm_init.pth` file that runs on any Python startup in the environment.

The reported exfiltration endpoint is `https://models.litellm.cloud/`. The payload collects environment variables, SSH keys, cloud credentials, Kubernetes configs, and other secrets.

## When to Use

Run this skill when the user wants to check whether a project, environment, host, or CI pipeline was affected by the compromised LiteLLM versions.

## Procedure

When invoked, run ALL of the following checks. Present results in a structured report at the end.

### 1. Check installed LiteLLM version

Run a single combined check that covers the system Python and detects project-local virtualenvs:

```bash
echo "=== System pip ==="
python3 -m pip show litellm 2>/dev/null | grep -E "^(Name|Version|Location):" || echo "litellm not installed (system python3)"

echo ""
echo "=== Project virtualenvs ==="
for vdir in .venv venv env .env .conda; do
  if [ -d "$vdir" ]; then
    echo "--- Found: $vdir ---"
    "$vdir/bin/python" -m pip show litellm 2>/dev/null | grep -E "^(Name|Version|Location):" || echo "litellm not installed in $vdir"
  fi
done

echo ""
echo "=== pipx ==="
pipx list 2>/dev/null | grep -i litellm || echo "litellm not in pipx"

echo ""
echo "=== conda ==="
conda list litellm 2>/dev/null | grep -v "^#" | head -5 || echo "conda not available or litellm not installed"

echo ""
echo "=== uv ==="
uv pip show litellm 2>/dev/null | grep -E "^(Name|Version|Location):" || echo "uv not available or litellm not installed"
```

### 2. Search for the malicious `.pth` file

Enumerate actual Python site-packages paths, then search only those directories (not the entire filesystem):

```bash
python3 -c "
import site, sys, os, subprocess

paths = set()
# system site-packages
try:
    for p in site.getsitepackages():
        paths.add(p)
except Exception:
    pass
# user site-packages
try:
    paths.add(site.getusersitepackages())
except Exception:
    pass
# sys.prefix lib
paths.add(os.path.join(sys.prefix, 'lib'))
# homebrew common paths on macOS
for extra in ['/opt/homebrew/lib/python3', '/usr/local/lib/python3']:
    if os.path.isdir(extra):
        paths.add(extra)

found = False
for p in sorted(paths):
    if not os.path.isdir(p):
        continue
    result = subprocess.run(
        ['find', p, '-maxdepth', '3', '-name', 'litellm_init.pth', '-type', 'f'],
        capture_output=True, text=True, timeout=10
    )
    for line in result.stdout.strip().splitlines():
        if line:
            print(f'FOUND: {line}')
            found = True
if not found:
    print('litellm_init.pth NOT found in any site-packages')
" 2>/dev/null
```

Also check project-local virtualenvs:

```bash
for vdir in .venv venv env .env .conda; do
  if [ -d "$vdir" ]; then
    find "$vdir" -maxdepth 4 -name "litellm_init.pth" -type f 2>/dev/null
  fi
done
echo "(project venv .pth search done)"
```

### 3. Search project manifests, lockfiles, CI configs, and Dockerfiles

Use the Grep tool (NOT bash grep) to search the project directory for references to `litellm`.

Run these Grep calls in parallel:

1. **Manifests & lockfiles** — search for pattern `litellm` with glob `*.{txt,toml,lock,cfg,ini}` (case-insensitive, output_mode: content)
2. **CI configs** — search for pattern `litellm` with glob `*.{yml,yaml}` (case-insensitive, output_mode: content)
3. **Dockerfiles** — search for pattern `litellm` with glob `Dockerfile*` (case-insensitive, output_mode: content)
4. **Python source** — search for pattern `litellm` with glob `*.py` (case-insensitive, output_mode: content)
5. **Pipfile** — search for pattern `litellm` with glob `Pipfile*` (case-insensitive, output_mode: content)
6. **Jenkinsfile** — search for pattern `litellm` with glob `Jenkinsfile*` (case-insensitive, output_mode: content)

**Risk classification for each match:**
- Contains `1.82.7` or `1.82.8` → **HIGH RISK**
- Contains `pip install litellm` with no version pin → **MEDIUM RISK**
- Contains `litellm` pinned to a version outside 1.82.7/1.82.8 → **LOW RISK**

**IMPORTANT:** Exclude matches inside `~/.claude/skills/` — those are this skill's own instructions, not project references.

### 4. Check for IOC domain in logs and source

Search for the exfiltration domain. Use the Grep tool for project files and bash for logs/history.

**Grep tool call:** search the project directory for pattern `models\.litellm\.cloud` (output_mode: content). Exclude files under `~/.claude/skills/`.

**Bash call (run in parallel with Grep):**

```bash
echo "=== Shell history ==="
grep -n "models\.litellm\.cloud\|litellm\.cloud" ~/.bash_history ~/.zsh_history 2>/dev/null || echo "No IOC domain found in shell history"

echo ""
echo "=== System logs (best effort, 10s timeout) ==="
timeout 10 grep -rln "models\.litellm\.cloud" /var/log/ 2>/dev/null || echo "No IOC domain found in /var/log (or not accessible)"
```

**IMPORTANT:** If Grep matches files inside `~/.claude/skills/`, discard those — they are this skill file, not real IOCs.

### 5. Check pip cache

Cross-platform cache check (works on both macOS and Linux):

```bash
echo "=== pip cache list ==="
python3 -m pip cache list litellm 2>/dev/null || echo "pip cache command unavailable or empty"

echo ""
echo "=== Cache directory contents ==="
# macOS path
ls -la ~/Library/Caches/pip/wheels/ 2>/dev/null | head -20
# Linux path
ls -la ~/.cache/pip/wheels/ 2>/dev/null | head -20
# If neither found
if [ ! -d ~/Library/Caches/pip/wheels ] && [ ! -d ~/.cache/pip/wheels ]; then
  echo "No pip wheel cache directory found"
fi
```

### 6. Check shell history for install commands

```bash
grep -n "pip.*install.*litellm" ~/.bash_history ~/.zsh_history ~/.local/share/fish/fish_history 2>/dev/null || echo "No litellm install found in shell history"
```

## Report Format

After running all checks, present a structured report:

```
## LiteLLM Supply-Chain Check Report

**Project:** <project path>
**Date:** <current date>
**Exposure Level:** HIGH / MEDIUM / LOW / NONE

### Findings

| Check                        | Result   | Details                    |
|------------------------------|----------|----------------------------|
| Installed version            | ...      | ...                        |
| litellm_init.pth found       | YES / NO | path if found              |
| IOC domain in logs/source    | YES / NO | locations if found         |
| Project manifest references  | YES / NO | files and versions found   |
| CI/CD references             | YES / NO | files and risk level       |
| Docker references            | YES / NO | files and risk level       |
| Pip cache                    | YES / NO | cached versions if any     |
| Shell history                | YES / NO | relevant commands          |

### Exposure Assessment

- **HIGH**: 1.82.7 or 1.82.8 installed, or litellm_init.pth found, or IOC domain contacted
- **MEDIUM**: Unpinned litellm install found in manifests/CI during incident window
- **LOW**: litellm referenced but pinned to safe version
- **NONE**: No litellm references found anywhere

### Recommended Actions

If HIGH or MEDIUM:
1. Rotate ALL credentials that were accessible on affected systems
2. Remove compromised package: `pip uninstall -y litellm && pip cache purge`
3. Rebuild affected environments from clean base images
4. Pin to safe version: `pip install "litellm<=1.82.6"`
5. Review outbound network logs for `models.litellm.cloud`
6. Notify security team

If LOW:
1. Verify pinned version is not in the compromised range
2. Consider adding hash verification to dependency pins

If NONE:
1. No action required for this project
```

## Important Notes

- Do NOT skip any check even if early results look clean
- The `.pth` file (1.82.8) executes on ANY Python startup, not just litellm imports
- Even if the package is now uninstalled, historical exposure still matters
- Credential rotation is the most critical remediation step
- A clean current state does not mean the system was never exposed — check history
- All bash commands use timeouts or scoped paths to avoid hanging
- Discard any Grep/search matches inside `~/.claude/skills/` — those are this skill file, not real IOCs
