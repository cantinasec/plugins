#!/usr/bin/env python3
"""
quickscan — deterministic dependency scanner.

Walks a project and the developer's local environment, surfacing patterns
worth a closer look across three vectors:

  1. pip packages   (requirements*.txt, Pipfile, pyproject.toml)
  2. VS Code extensions  (~/.vscode/extensions/, ~/.cursor/extensions/)
  3. MCP servers    (~/.claude.json, claude_desktop_config.json, project .mcp.json)

Produces a JSON file in the shape the quickscan renderer and enricher
already consume. Quickscan is a heads-up tool, not a security audit —
the output is a list of *warnings*, never findings or verdicts.

Usage:
    python3 scan.py [path] [--out PATH] [--no-osv] [--no-env] [--quiet]

Defaults:
    path = cwd
    out  = /tmp/quickscan-findings.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Iterable

# ─────────────────────────────────────────────────────────────────────────────
# Constants — knobs for the per-vector checks
# ─────────────────────────────────────────────────────────────────────────────

TYPOSQUAT_TARGETS = [
    "requests", "urllib3", "numpy", "pandas", "pillow", "cryptography",
    "pyyaml", "boto3", "flask", "django", "fastapi", "pytest",
    "setuptools", "tensorflow", "torch", "transformers", "openai",
    "anthropic", "langchain",
]

TRUSTED_VSCODE_PUBLISHERS = {
    "github", "redhat", "dbaeumer", "esbenp", "bradlc", "eamodio",
    "streetsidesoftware", "vscodevim", "anthropic", "continue",
}
# any publisher starting with "ms-" is also trusted (Microsoft's own family)

VSCODE_WELL_KNOWN_NAMES = {
    # canonical display name (lowercase) → expected publisher
    "eslint": "dbaeumer",
    "prettier - code formatter": "esbenp",
    "tailwind css intellisense": "bradlc",
    "gitlens — git supercharged": "eamodio",
    "code spell checker": "streetsidesoftware",
    "vim": "vscodevim",
    "claude code": "anthropic",
}

TRUSTED_NPM_SCOPES = {
    "@modelcontextprotocol", "@anthropic-ai", "@cantinasec",
    "@vercel", "@supabase", "@stripe", "@github",
}

HIGH_VALUE_DATA_HINTS = ["gmail", "gdrive", "slack", "notion", "linear", "stripe", "aws", "okta"]

DESTRUCTIVE_TOOLS = {"bash", "write_file", "execute_sql", "send_message"}

CRED_RE = re.compile(r"^(sk-|sk_live_|xoxb-|ghp_|AKIA|AIza)[A-Za-z0-9_-]{16,}$")

# PEP 508 / requirements.txt rough parser
PIP_DEP_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]+\])?\s*"
    r"((?:==|>=|<=|>|<|~=|!=|@)\s*[^;\s#]+)?"
)

CURL_PIPE_SHELL_RE = re.compile(r"(curl|wget)\b[^|]*\|\s*(sh|bash|zsh)\b|iex\s*\(", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
# Tiny helpers
# ─────────────────────────────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(a) + 1))
    for i, cb in enumerate(b, start=1):
        cur = [i]
        for j, ca in enumerate(a, start=1):
            cost = 0 if ca == cb else 1
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _warn(items: list[dict], concern: str, vector: str, target: str, evidence: str, why: str, fix: str) -> None:
    items.append({
        "concern": concern,
        "vector":  vector,
        "target":  target,
        "evidence": evidence,
        "why":     why,
        "suggested_fix": fix,
    })


def _load_toml(path: pathlib.Path) -> dict | None:
    """Best-effort TOML load. Returns None if tomllib unavailable or parse fails."""
    try:
        import tomllib  # Python 3.11+
        return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
            return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
        except ImportError:
            return None
    except Exception:
        return None


def _regex_extract_pep508(text: str) -> list[str]:
    """
    Fallback when no TOML library is available (e.g. Python 3.9, no tomli).
    Pulls any quoted string that looks like a PEP 508 dependency spec out
    of a TOML or text file. Tolerates both single and double quotes.
    Filters out the `python` interpreter spec which appears in poetry deps.
    """
    out: list[str] = []
    for pattern in (r'"([^"]+)"', r"'([^']+)'"):
        for m in re.finditer(pattern, text):
            spec = m.group(1).strip()
            # rough PEP 508 shape: starts with name, contains a version op
            if not re.match(r"^[A-Za-z][A-Za-z0-9._-]*", spec):
                continue
            if not re.search(r"[~!=<>]=?", spec):
                continue
            # skip python interpreter constraint
            if spec.lower().startswith("python"):
                first_token = re.split(r"[\s~!=<>]", spec, 1)[0].lower()
                if first_token == "python":
                    continue
            # skip obvious non-PEP-508 patterns (urls, etc.)
            if "://" in spec:
                continue
            out.append(spec)
    return out


def _parse_pep508(spec: str) -> tuple[str, str | None]:
    """Return (package_name, pinned_version_or_None)."""
    m = PIP_DEP_RE.match(spec)
    if not m:
        return spec.strip(), None
    name = m.group(1)
    op_ver = m.group(3) or ""
    if op_ver.startswith("=="):
        return name, op_ver[2:].strip()
    return name, None


def _safe_relpath(p: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def _log(quiet: bool, *args: Any) -> None:
    if not quiet:
        print(*args, file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# Vector 1 — pip packages
# ─────────────────────────────────────────────────────────────────────────────

def scan_pip(project_root: pathlib.Path, *, use_osv: bool, quiet: bool) -> tuple[int, list[dict]]:
    items: list[dict] = []
    deps: list[dict] = []  # {name, pinned, evidence (str), origin (Path)}
    manifests: list[pathlib.Path] = []

    # Find manifests, top-level only (don't recurse into .venv etc.)
    top_dir = project_root
    for name in ("Pipfile", "pyproject.toml", "setup.cfg", "environment.yml"):
        p = top_dir / name
        if p.is_file():
            manifests.append(p)
    for p in top_dir.glob("requirements*.txt"):
        if p.is_file():
            manifests.append(p)
    # one level deep (e.g. "requirements/prod.txt")
    for sub in top_dir.iterdir() if top_dir.is_dir() else []:
        if sub.is_dir() and not sub.name.startswith(".") and sub.name not in ("node_modules", ".venv", "venv", "__pycache__", ".tox"):
            for p in sub.glob("requirements*.txt"):
                if p.is_file():
                    manifests.append(p)

    # Parse each
    for path in manifests:
        rel = _safe_relpath(path, project_root)
        if path.name.endswith(".txt"):
            content = path.read_text(encoding="utf-8", errors="replace")
            saw_anything_in_file = False
            for lineno, raw in enumerate(content.splitlines(), start=1):
                # strip comments and continuations
                line = raw.split("#", 1)[0].rstrip()
                if not line.strip() or line.lstrip().startswith("-"):
                    # check git+
                    if line.lstrip().startswith(("-e git+", "git+")):
                        _warn(items, "high", "pip",
                              line.strip()[:120],
                              f"{rel}:{lineno}",
                              "Direct-from-git install bypasses PyPI's tamper-detection — the install pulls whatever's at HEAD of the named ref.",
                              "Replace with a tagged PyPI release (`pkg==1.2.3`) or pin the URL to a specific commit SHA.")
                    continue
                name, pinned = _parse_pep508(line)
                if not name or name.startswith("-"):
                    continue
                saw_anything_in_file = True
                deps.append({"name": name, "pinned": pinned, "evidence": f"{rel}:{lineno}", "origin": path})
            # hash pinning check
            if saw_anything_in_file and "--hash=sha256:" not in content:
                _warn(items, "low", "pip",
                      rel,
                      rel,
                      "No hash pinning is in use. A bad mirror or CDN cache could substitute a package even when the version is pinned.",
                      f"Generate hash-pinned requirements with `pip-compile --generate-hashes {pathlib.PurePath(rel).with_suffix('.in')} -o {rel}` (or hand-add `--hash=sha256:...` to each line).")
        elif path.name == "Pipfile":
            data = _load_toml(path)
            if data is not None:
                for section in ("packages", "dev-packages"):
                    for name, spec in data.get(section, {}).items():
                        pinned = None
                        if isinstance(spec, str):
                            if spec.startswith("=="):
                                pinned = spec[2:]
                        elif isinstance(spec, dict) and isinstance(spec.get("version"), str):
                            v = spec["version"]
                            if v.startswith("=="):
                                pinned = v[2:]
                        deps.append({"name": name, "pinned": pinned, "evidence": f"{rel}::{section}.{name}", "origin": path})
            else:
                # Fallback: regex over the raw text
                content = path.read_text(encoding="utf-8", errors="replace")
                for spec in _regex_extract_pep508(content):
                    name, pinned = _parse_pep508(spec)
                    if name:
                        deps.append({"name": name, "pinned": pinned, "evidence": f"{rel}::{spec}", "origin": path})
        elif path.name == "pyproject.toml":
            data = _load_toml(path)
            if data is not None:
                # PEP 621
                proj = data.get("project", {})
                for spec in proj.get("dependencies", []) or []:
                    name, pinned = _parse_pep508(spec)
                    if name:
                        deps.append({"name": name, "pinned": pinned, "evidence": f"{rel}::project.dependencies[{spec}]", "origin": path})
                for extra_name, dlist in (proj.get("optional-dependencies") or {}).items():
                    for spec in dlist:
                        name, pinned = _parse_pep508(spec)
                        if name:
                            deps.append({"name": name, "pinned": pinned, "evidence": f"{rel}::optional-dependencies.{extra_name}[{spec}]", "origin": path})
                # Poetry
                poetry_deps = (data.get("tool", {}).get("poetry", {}) or {}).get("dependencies", {}) or {}
                for name, spec in poetry_deps.items():
                    if name == "python":
                        continue
                    pinned: str | None = None
                    if isinstance(spec, str) and re.match(r"^\d", spec):
                        pinned = spec
                    elif isinstance(spec, dict) and isinstance(spec.get("version"), str) and re.match(r"^\d", spec["version"]):
                        pinned = spec["version"]
                    deps.append({"name": name, "pinned": pinned, "evidence": f"{rel}::tool.poetry.dependencies.{name}", "origin": path})
            else:
                # Fallback: regex over the raw text (Python <3.11 without `tomli`)
                content = path.read_text(encoding="utf-8", errors="replace")
                for spec in _regex_extract_pep508(content):
                    name, pinned = _parse_pep508(spec)
                    if name:
                        deps.append({"name": name, "pinned": pinned, "evidence": f"{rel}::{spec}", "origin": path})

    # Deduplicate by (name, evidence) — keep first
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for d in deps:
        k = (d["name"].lower(), d["evidence"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(d)
    deps = deduped

    # ── Checks per-dep ──
    target_set = set(TYPOSQUAT_TARGETS)
    for d in deps:
        name = d["name"]
        nlower = name.lower()
        # unpinned
        if not d["pinned"]:
            _warn(items, "medium", "pip",
                  name,
                  d["evidence"],
                  f"`{name}` has no `==` version pin, so the next install can land a different release.",
                  f"Pin to a known-good version: `{name}==<x.y.z>` (or regenerate with `pip-compile`).")
        # typosquat — Levenshtein ≤ 2 to a target, but not the target itself
        if nlower not in target_set:
            for t in TYPOSQUAT_TARGETS:
                if abs(len(nlower) - len(t)) <= 2 and _levenshtein(nlower, t) <= 2:
                    _warn(items, "high", "pip",
                          name,
                          d["evidence"],
                          f"`{name}` is one or two edits away from the well-known package `{t}`. This is the typical shape of a typosquat.",
                          f"Confirm the package is intentional and from a trusted maintainer. If not, replace with `{t}` (verify on PyPI first).")
                    break

    # ── OSV batch ──
    if use_osv and deps:
        pinned_deps = [d for d in deps if d["pinned"]]
        if pinned_deps:
            _log(quiet, f"  scan: pip — querying OSV for {len(pinned_deps)} pinned dep(s)...")
            try:
                osv_hits = _osv_batch_query([(d["name"], d["pinned"], "PyPI") for d in pinned_deps])
                for d, hits in zip(pinned_deps, osv_hits):
                    for h in hits[:1]:  # one warning per package; mention count if more
                        more = f" ({len(hits)} advisories total)" if len(hits) > 1 else ""
                        _warn(items, "high", "pip",
                              f"{d['name']}=={d['pinned']}",
                              d["evidence"],
                              f"OSV lists advisory `{h}` against `{d['name']}=={d['pinned']}`{more}.",
                              f"Bump to a patched release: check https://osv.dev/vulnerability/{h} for the fixed version and pin to that.")
            except Exception as e:
                _log(quiet, f"  scan: pip — OSV query failed ({e}); skipping vuln check")

    return len(deps), items


def _osv_batch_query(packages: list[tuple[str, str, str]]) -> list[list[str]]:
    """Query OSV.dev /v1/querybatch. Returns parallel list of vuln-id lists per input."""
    body = {
        "queries": [
            {"package": {"name": name, "ecosystem": eco}, "version": ver}
            for (name, ver, eco) in packages
        ]
    }
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = json.load(resp)
    out: list[list[str]] = []
    for r in data.get("results", []):
        out.append([v.get("id", "") for v in (r.get("vulns") or [])])
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Vector 2 — VS Code extensions
# ─────────────────────────────────────────────────────────────────────────────

def scan_vscode(*, quiet: bool) -> tuple[int, list[dict]]:
    items: list[dict] = []
    scan_dirs = [
        pathlib.Path.home() / ".vscode" / "extensions",
        pathlib.Path.home() / ".cursor" / "extensions",
        pathlib.Path.home() / ".vscode-insiders" / "extensions",
    ]
    scanned = 0
    for d in scan_dirs:
        if not d.is_dir():
            continue
        for ext_dir in d.iterdir():
            pkg = ext_dir / "package.json"
            if not pkg.is_file():
                continue
            scanned += 1
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            publisher = (data.get("publisher") or "").strip()
            name = data.get("name") or ext_dir.name
            display_name = (data.get("displayName") or "").strip()
            ext_id = f"{publisher}.{name}" if publisher else name
            evidence = _safe_relpath(pkg, pathlib.Path.home())

            # Publisher trust
            trusted = publisher.lower() in TRUSTED_VSCODE_PUBLISHERS or publisher.lower().startswith("ms-")
            if not trusted and publisher:
                _warn(items, "medium", "vscode",
                      ext_id,
                      evidence,
                      f"Publisher `{publisher}` isn't on the trusted-publishers allowlist quickscan ships with. That doesn't mean the publisher is bad — it means trust hasn't been confirmed here.",
                      f"Verify the publisher on the VS Code Marketplace and either trust it locally or `code --uninstall-extension {ext_id}`.")

            # Display-name impersonation
            if display_name and publisher:
                expected = VSCODE_WELL_KNOWN_NAMES.get(display_name.lower())
                if expected and expected.lower() != publisher.lower():
                    _warn(items, "high", "vscode",
                          ext_id,
                          evidence,
                          f"The display name `{display_name}` matches a well-known extension that's normally published by `{expected}`, but this one is from `{publisher}`. Worth checking it isn't an impersonator.",
                          f"Compare against the canonical extension on the VS Code Marketplace. If this isn't the real one: `code --uninstall-extension {ext_id}`.")

            # Custom updateUrl
            update_url = data.get("updateUrl") or ""
            if isinstance(update_url, str) and update_url and "marketplace.visualstudio.com" not in update_url:
                _warn(items, "high", "vscode",
                      ext_id,
                      evidence,
                      f"Extension has a custom `updateUrl` (`{update_url}`) outside the official Marketplace — updates can come from anywhere the URL points.",
                      "Remove the extension and reinstall from the Marketplace if you need it, or confirm the custom update host is one you control.")

            # Broad untrusted-workspace support
            caps = data.get("capabilities") or {}
            ut = caps.get("untrustedWorkspaces") or {}
            if isinstance(ut, dict) and ut.get("supported") is True and not ut.get("restrictedConfigurations"):
                _warn(items, "high", "vscode",
                      ext_id,
                      evidence + "::capabilities.untrustedWorkspaces",
                      "Extension claims to support untrusted workspaces with no restrictions. In an untrusted-workspace activation, all of its code runs anyway.",
                      "Disable the extension in untrusted workspaces, or remove it if you don't actively need it.")

    return scanned, items


# ─────────────────────────────────────────────────────────────────────────────
# Vector 3 — MCP servers
# ─────────────────────────────────────────────────────────────────────────────

def scan_mcp(project_root: pathlib.Path, *, scan_env: bool, quiet: bool) -> tuple[int, list[dict]]:
    items: list[dict] = []
    sources: list[tuple[pathlib.Path, str]] = []  # (path, scope_label)

    if scan_env:
        for p in [
            pathlib.Path.home() / ".claude.json",
            pathlib.Path.home() / ".claude" / "settings.json",
            pathlib.Path.home() / ".claude" / "mcp.json",
            pathlib.Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ]:
            if p.is_file():
                sources.append((p, "global"))

    for name in (".mcp.json", ".claude/settings.json", ".claude/mcp.json"):
        p = project_root / name
        if p.is_file():
            sources.append((p, "project"))

    scanned = 0
    for path, scope in sources:
        rel_or_home = _safe_relpath(path, pathlib.Path.home())
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        servers = data.get("mcpServers") or {}
        if not isinstance(servers, dict):
            continue
        for srv_name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            scanned += 1
            command = cfg.get("command") or ""
            args = cfg.get("args") or []
            env_dict = cfg.get("env") or {}
            url = cfg.get("url") or ""
            evidence_base = f"{rel_or_home} :: mcpServers.{srv_name}"

            # Unpinned npx / uvx
            if command in ("npx", "uvx") and isinstance(args, list):
                for arg in args:
                    if not isinstance(arg, str) or arg.startswith("-"):
                        continue
                    if "@" not in arg.lstrip("@"):  # scoped pkgs have leading @
                        pkg = arg
                        _warn(items, "high", "mcp",
                              f"{command} {pkg}",
                              evidence_base + ".args",
                              f"`{command} {pkg}` has no `@<version>` pin — the next run can pull a different release silently.",
                              f"Pin the version, e.g. `{command} {pkg}@<x.y.z>`. For maximum stability, install locally and reference the binary path.")
                        break  # one warning per server is enough

            # curl-pipe-shell installer (in command, args, or anywhere stringy)
            stringy = [command] + [str(a) for a in args if isinstance(a, (str, int))] + [str(v) for v in env_dict.values() if isinstance(v, str)]
            for s in stringy:
                if CURL_PIPE_SHELL_RE.search(s):
                    _warn(items, "high", "mcp",
                          srv_name,
                          evidence_base,
                          "MCP entry includes a curl-pipe-shell pattern. Running it means executing whatever the URL serves at the moment of the call.",
                          "Replace with a pinned, vendored install (`npm install <pkg>@<version>` or a versioned binary download), then reference the local binary.")
                    break

            # HTTP non-localhost
            if isinstance(url, str) and url.startswith("http://"):
                host = url.split("/")[2].split(":")[0] if "://" in url else ""
                if host and host not in ("localhost", "127.0.0.1", "::1"):
                    _warn(items, "high", "mcp",
                          srv_name,
                          evidence_base + ".url",
                          f"MCP URL is plain HTTP (`{url}`). Tool calls and tool results travel in plaintext over this connection.",
                          "Switch to https:// (provision a TLS cert via Caddy or Tailscale Funnel), or move the server behind localhost.")

            # Unknown npm scope
            for arg in (args if isinstance(args, list) else []):
                if isinstance(arg, str) and arg.startswith("@"):
                    scope = arg.split("/", 1)[0]
                    if scope.lower() not in TRUSTED_NPM_SCOPES:
                        _warn(items, "medium", "mcp",
                              arg.split("@")[0] if "@" in arg[1:] else arg,
                              evidence_base + ".args",
                              f"npm scope `{scope}` isn't on the trusted-scopes allowlist quickscan ships with. The package isn't necessarily bad — trust just hasn't been confirmed here.",
                              f"Look up `{arg}` on npmjs.com and confirm the maintainer is who you expect.")
                        break

            # High-value data scope at global
            sname_l = srv_name.lower()
            if scope == "global":
                for hint in HIGH_VALUE_DATA_HINTS:
                    if hint in sname_l:
                        _warn(items, "medium", "mcp",
                              srv_name,
                              evidence_base + " (global scope)",
                              f"The `{srv_name}` MCP touches a high-value data source (`{hint}`) and is configured at global scope. Prompt injection in any project's tool result can act on these credentials.",
                              f"Move `{srv_name}` out of `~/.claude.json` and into a per-project `.mcp.json` so the credential's blast radius is one project, not all of them.")
                        break

            # Credential-shaped strings in env
            if isinstance(env_dict, dict):
                for env_k, env_v in env_dict.items():
                    if isinstance(env_v, str) and CRED_RE.match(env_v):
                        prefix = env_v.split("_")[0] if "_" in env_v else env_v[:6]
                        _warn(items, "high", "mcp",
                              srv_name,
                              evidence_base + f".env.{env_k}",
                              f"`env.{env_k}` looks like a credential (matches the `{prefix}…` pattern). If this is committed to a config file, treat it as exposed.",
                              "If confirmed: revoke the credential at the issuer FIRST, then rotate and use an env-var reference instead of a literal value.")
                        break

        # alwaysAllow destructive tools (in Claude settings files)
        for tool in (data.get("alwaysAllow") if isinstance(data.get("alwaysAllow"), list) else []):
            if isinstance(tool, str) and tool in DESTRUCTIVE_TOOLS:
                _warn(items, "high", "mcp",
                      f"alwaysAllow: {tool}",
                      f"{rel_or_home} :: alwaysAllow",
                      f"`{tool}` is in `alwaysAllow`, so every invocation runs without confirmation. Prompt injection in a tool result can use it silently.",
                      f"Remove `{tool}` from the `alwaysAllow` list. Approve each invocation interactively, or scope `alwaysAllow` to read-only tools.")

    return scanned, items


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run(project_root: pathlib.Path, *, use_osv: bool, scan_env: bool, quiet: bool) -> dict:
    _log(quiet, f"scan: quickscan — scanning {project_root}")

    pip_scanned, pip_warnings = scan_pip(project_root, use_osv=use_osv, quiet=quiet)
    _log(quiet, f"  scan: pip — {pip_scanned} package(s), {len(pip_warnings)} warning(s)")

    vscode_scanned, vscode_warnings = (0, []) if not scan_env else scan_vscode(quiet=quiet)
    if scan_env:
        _log(quiet, f"  scan: vscode — {vscode_scanned} extension(s), {len(vscode_warnings)} warning(s)")

    mcp_scanned, mcp_warnings = scan_mcp(project_root, scan_env=scan_env, quiet=quiet)
    _log(quiet, f"  scan: mcp — {mcp_scanned} server(s), {len(mcp_warnings)} warning(s)")

    all_warnings = pip_warnings + vscode_warnings + mcp_warnings
    counts = {"high": 0, "medium": 0, "low": 0}
    for w in all_warnings:
        c = (w.get("concern") or "low").lower()
        counts[c] = counts.get(c, 0) + 1

    return {
        "project_path": str(project_root),
        "timestamp": _dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "vectors": {
            "pip":    {"scanned": pip_scanned,    "warnings": len(pip_warnings)},
            "vscode": {"scanned": vscode_scanned, "warnings": len(vscode_warnings)},
            "mcp":    {"scanned": mcp_scanned,    "warnings": len(mcp_warnings)},
        },
        "concern_counts": counts,
        "warnings": all_warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default=".", help="Project path to scan (default: cwd)")
    parser.add_argument("--out", default="/tmp/quickscan-findings.json", help="Output JSON path")
    parser.add_argument("--no-osv", action="store_true", help="Skip OSV vuln-database queries (offline / fast mode)")
    parser.add_argument("--no-env", action="store_true", help="Skip global VS Code + MCP scans (project-only)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress to stderr")
    args = parser.parse_args()

    project_root = pathlib.Path(args.path).expanduser().resolve()
    if not project_root.is_dir():
        print(f"scan: error — path is not a directory: {project_root}", file=sys.stderr)
        return 2

    payload = run(
        project_root,
        use_osv=not args.no_osv,
        scan_env=not args.no_env,
        quiet=args.quiet,
    )
    pathlib.Path(args.out).write_text(json.dumps(payload, indent=2))
    _log(args.quiet, f"scan: wrote {args.out}")
    print(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
