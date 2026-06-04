#!/usr/bin/env python3
"""
quickscan breakdown renderer.

Reads a warnings JSON file, renders a self-contained Cantina-branded HTML
breakdown, writes it to a timestamped path under the system temp dir, and
opens it in the default browser.

Quickscan is a heads-up tool, not a security audit. The output surfaces
patterns in dependencies that may be worth a closer look; it does not
issue findings, verdicts, or audit conclusions.

The generated HTML includes:
- A "Print / Save as PDF" button (calls window.print() — print CSS strips
  the toolbar, CTA, and decorative backgrounds for clean PDFs)
- A "Download JSON" button (embeds the raw warnings JSON as a data URI
  so the user can re-feed it to another tool)

Usage:
    python3 render_report.py <warnings.json> [--no-open]
    cat warnings.json | python3 render_report.py - [--no-open]

Warnings JSON shape:
{
  "project_path": "/path/scanned",
  "timestamp": "2026-05-20T14:15:30Z",   # optional; auto-filled if missing
  "vectors": {
    "pip":    {"scanned": N, "warnings": N},
    "vscode": {"scanned": N, "warnings": N},
    "mcp":    {"scanned": N, "warnings": N}
  },
  "concern_counts": {"high": N, "medium": N, "low": N},
  "warnings": [
    {"concern": "high|medium|low", "vector": "pip|vscode|mcp",
     "target": "...", "evidence": "...", "why": "...", "suggested_fix": "..."}
  ]
}
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import html
import json
import pathlib
import subprocess
import sys
import tempfile


# BD email funnel hook. Replace when contact preferences change.
CONTACT_EMAIL = "aidan@spearbit.com"


CONCERN_COLORS = {
    "high":   "#ea580c",
    "medium": "#ca8a04",
    "low":    "#71717a",
}

CONCERN_LABELS = {
    "high":   "Worth checking soon",
    "medium": "Worth checking",
    "low":    "Minor pattern to note",
}

VECTOR_LABELS = {
    "pip":    "pip packages",
    "vscode": "VS Code extensions",
    "mcp":    "MCP servers",
}


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _badge(label: str, color: str, size: str = "md") -> str:
    fs = "11px" if size == "sm" else "12px"
    dot = "7px" if size == "sm" else "9px"
    return (
        f'<span style="display:inline-flex;align-items:center;gap:7px;'
        f'font-weight:600;font-size:{fs};color:{color};'
        f'letter-spacing:0.02em;">'
        f'<span style="width:{dot};height:{dot};border-radius:50%;background:{color};'
        f'box-shadow:0 0 0 4px {color}1f;"></span>'
        f'{_esc(label)}</span>'
    )


def _vector_card(key: str, data: dict) -> str:
    scanned = data.get("scanned", 0)
    # Accept both new ("warnings") and legacy ("findings") keys for safety.
    warnings = data.get("warnings", data.get("findings", 0))
    label = VECTOR_LABELS.get(key, key)
    return f"""
      <div class="vector-card">
        <div class="vector-label">{_esc(label)}</div>
        <div class="vector-numbers">
          <div><span class="num">{scanned}</span><span class="unit">scanned</span></div>
          <div><span class="num">{warnings}</span><span class="unit">warnings</span></div>
        </div>
      </div>
    """


def _context_block(rem: dict | None) -> str:
    if not rem:
        return ""
    return f"""
        <div class="rem-divider"><span>AI-suggested context</span></div>
        <dl class="finding-body rem-body">
          <dt>Likely reason</dt><dd>{_esc(rem.get('root_cause', '—'))}</dd>
          <dt>Prevention</dt><dd>{_esc(rem.get('prevention', '—'))}</dd>
        </dl>
    """


def _warning_card(f: dict) -> str:
    # Accept the new "concern" field; fall back to legacy "severity" if older
    # producers emit it. Map legacy CRITICAL down to high — we no longer
    # distinguish the two.
    concern_raw = (f.get("concern") or f.get("severity") or "low").lower()
    if concern_raw == "critical":
        concern_raw = "high"
    concern = concern_raw if concern_raw in CONCERN_COLORS else "low"
    color = CONCERN_COLORS[concern]
    concern_label = CONCERN_LABELS[concern]
    vector_label = VECTOR_LABELS.get(f.get("vector", ""), f.get("vector", "—"))
    fix_text = f.get("suggested_fix") or f.get("fix", "—")
    return f"""
      <article class="finding" style="border-left-color:{color};">
        <header class="finding-head">
          {_badge(concern_label, color)}
          <span class="finding-vector">{_esc(vector_label)}</span>
          <span class="finding-target">{_esc(f.get('target', '—'))}</span>
        </header>
        <dl class="finding-body">
          <dt>What we saw</dt><dd><code>{_esc(f.get('evidence', '—'))}</code></dd>
          <dt>Why it caught our eye</dt><dd>{_esc(f.get('why', '—'))}</dd>
          <dt>One thing you could do</dt><dd>{_esc(fix_text)}</dd>
        </dl>
        {_context_block(f.get('remediation'))}
      </article>
    """


def render(findings: dict) -> str:
    ts = findings.get("timestamp") or _dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    project = findings.get("project_path", "—")
    vectors = findings.get("vectors", {})

    # Embed a copy of the JSON as a data: URI so the "Download JSON" button
    # works offline with no server roundtrip.
    json_blob = json.dumps(findings, indent=2)
    json_b64 = base64.b64encode(json_blob.encode("utf-8")).decode("ascii")
    json_data_uri = f"data:application/json;base64,{json_b64}"
    download_stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    # Accept new keys (concern_counts, warnings) and fall back to legacy ones
    # (severity_counts, findings) so older producers still render.
    counts_raw = findings.get("concern_counts") or findings.get("severity_counts") or {}
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for k, v in counts_raw.items():
        kl = k.lower()
        if kl == "critical":
            counts["high"] = counts.get("high", 0) + int(v or 0)
        elif kl in counts:
            counts[kl] = counts.get(kl, 0) + int(v or 0)

    items = findings.get("warnings") or findings.get("findings") or []

    def _concern_key(x: dict) -> str:
        raw = (x.get("concern") or x.get("severity") or "low").lower()
        if raw == "critical":
            raw = "high"
        return raw if raw in CONCERN_COLORS else "low"

    order = {"high": 0, "medium": 1, "low": 2}
    items_sorted = sorted(items, key=lambda x: order.get(_concern_key(x), 3))
    total = len(items_sorted)

    if items_sorted:
        findings_html = "\n".join(_warning_card(f) for f in items_sorted)
    else:
        findings_html = (
            '<div class="empty">'
            '<div class="empty-mark">✓</div>'
            '<div class="empty-headline">Nothing unusual surfaced</div>'
            '<div>That doesn\'t mean everything is safe — just that quickscan '
            'didn\'t spot any of the patterns it watches for.</div>'
            '</div>'
        )

    # Inline concern summary — sits in the hero next to the totals.
    sev_summary_parts = []
    for s in ("high", "medium", "low"):
        n = counts.get(s, 0)
        if n == 0:
            continue
        sev_summary_parts.append(
            f'<span class="sev-inline" style="color:{CONCERN_COLORS[s]};">'
            f'<span class="sev-inline-dot" style="background:{CONCERN_COLORS[s]};'
            f'box-shadow:0 0 0 3px {CONCERN_COLORS[s]}1f;"></span>'
            f'{n} {s}</span>'
        )
    sev_summary = " ".join(sev_summary_parts) or '<span class="sev-inline-empty">no warnings surfaced</span>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>quickscan breakdown — {_esc(project)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {{
    --brand:        #F05E00;
    --brand-soft:   rgba(240,94,0,0.08);
    --brand-line:   rgba(240,94,0,0.22);
    --bg:           #fbfaf8;
    --surface:      rgba(255,255,255,0.66);
    --surface-2:    rgba(255,255,255,0.92);
    --border:       rgba(15,15,20,0.07);
    --border-strong: rgba(15,15,20,0.12);
    --text:         #0a0a0c;
    --text-2:       #29292e;
    --muted:        #6e6e76;
    --muted-2:      #9a9aa3;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0;
    background:
      radial-gradient(ellipse 60% 50% at 88% -10%, rgba(240,94,0,0.10) 0%, transparent 60%),
      radial-gradient(ellipse 50% 40% at 5% 105%, rgba(100,90,220,0.07) 0%, transparent 60%),
      radial-gradient(ellipse 80% 60% at 50% 50%, rgba(255,255,255,0.5) 0%, transparent 100%),
      var(--bg);
    background-attachment: fixed;
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Inter', system-ui, 'Segoe UI', sans-serif;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }}
  .wrap {{ max-width: 1320px; margin: 0 auto; padding: 36px 40px 64px; }}

  /* Liquid glass surface — used everywhere */
  .glass {{
    background: var(--surface);
    border: 1px solid var(--border);
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    box-shadow:
      0 1px 2px rgba(15,15,20,0.04),
      0 8px 24px rgba(15,15,20,0.04),
      inset 0 1px 0 rgba(255,255,255,0.6);
  }}

  header.brandbar {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 24px;
  }}
  .brand {{ display: flex; align-items: center; gap: 10px; }}
  .brand-mark {{
    font-size: 13px; font-weight: 700; color: var(--brand);
    letter-spacing: 0.10em; text-transform: uppercase;
  }}
  .brand-sub {{
    color: var(--muted); font-size: 13px; letter-spacing: 0.01em;
    font-weight: 500;
  }}
  .brand-sub::before {{
    content: "·"; margin: 0 6px; color: var(--muted-2);
  }}
  .ts {{
    color: var(--muted); font-size: 12px;
    font-variant-numeric: tabular-nums; letter-spacing: 0.01em;
  }}

  /* Hero card */
  .hero {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 28px 32px;
    margin-bottom: 22px;
    backdrop-filter: blur(28px) saturate(180%);
    -webkit-backdrop-filter: blur(28px) saturate(180%);
    box-shadow:
      0 2px 4px rgba(15,15,20,0.05),
      0 20px 48px rgba(15,15,20,0.10),
      0 40px 80px rgba(15,15,20,0.05),
      inset 0 1px 0 rgba(255,255,255,0.75);
  }}
  .hero-row {{
    display: flex; align-items: center; justify-content: space-between;
    gap: 24px; flex-wrap: wrap;
  }}
  .hero-title {{
    font-size: 30px; font-weight: 600; letter-spacing: -0.02em;
    color: var(--text); margin: 0 0 6px; line-height: 1.1;
  }}
  .hero-project {{
    color: var(--muted); font-size: 13px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    word-break: break-all;
  }}
  .hero-stat {{
    display: flex; flex-direction: column; align-items: flex-end; gap: 6px;
  }}
  .totals {{
    display: inline-flex; align-items: baseline; gap: 8px;
    color: var(--muted); font-size: 13px; font-weight: 500;
  }}
  .totals strong {{
    color: var(--text); font-size: 28px; font-weight: 600;
    font-variant-numeric: tabular-nums; letter-spacing: -0.02em;
  }}

  /* Inline concern breakdown — sits under the totals */
  .sev-summary {{
    display: flex; gap: 14px; align-items: center;
    font-size: 12.5px; font-weight: 500;
  }}
  .sev-inline {{
    display: inline-flex; align-items: center; gap: 6px;
    letter-spacing: 0.01em;
    font-variant-numeric: tabular-nums;
  }}
  .sev-inline-dot {{
    width: 7px; height: 7px; border-radius: 50%;
  }}
  .sev-inline-empty {{
    color: var(--muted-2); font-size: 12px; font-style: italic;
  }}

  /* Vector cards */
  .vectors {{
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;
    margin-bottom: 28px;
  }}
  .vector-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px 18px;
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    box-shadow:
      0 1px 2px rgba(15,15,20,0.04),
      0 10px 24px rgba(15,15,20,0.06),
      inset 0 1px 0 rgba(255,255,255,0.7);
  }}
  .vector-label {{
    font-size: 11px; color: var(--muted); font-weight: 500;
    letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 8px;
  }}
  .vector-numbers {{ display: flex; gap: 22px; }}
  .vector-numbers .num {{
    font-size: 20px; font-weight: 600;
    font-variant-numeric: tabular-nums; letter-spacing: -0.02em;
  }}
  .vector-numbers .unit {{
    display: block; font-size: 11px; color: var(--muted);
    margin-top: 2px;
  }}

  /* Section heading */
  h2.section {{
    font-size: 12px; color: var(--muted); font-weight: 500;
    letter-spacing: 0.06em; text-transform: uppercase;
    margin: 0 0 12px;
  }}

  /* Warning cards */
  .finding {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--brand);
    border-radius: 14px;
    padding: 18px 22px;
    margin-bottom: 12px;
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    box-shadow:
      0 1px 2px rgba(15,15,20,0.04),
      0 12px 28px rgba(15,15,20,0.07),
      0 24px 56px rgba(15,15,20,0.04),
      inset 0 1px 0 rgba(255,255,255,0.65);
  }}
  .finding-head {{
    display: flex; align-items: center; gap: 14px;
    flex-wrap: wrap; margin-bottom: 14px;
  }}
  .finding-vector {{
    color: var(--muted); font-size: 11px; font-weight: 500;
    letter-spacing: 0.05em; text-transform: uppercase;
  }}
  .finding-target {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 13.5px; font-weight: 500;
    color: var(--text-2); word-break: break-all;
  }}
  .finding-body {{
    margin: 0; display: grid;
    grid-template-columns: 140px 1fr; gap: 8px 18px;
  }}
  .finding-body dt {{
    color: var(--muted); font-size: 12px; font-weight: 500;
    padding-top: 2px;
  }}
  .finding-body dd {{
    margin: 0; font-size: 14px; line-height: 1.55;
    color: var(--text-2);
  }}
  .finding-body code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px;
    background: rgba(15,15,20,0.04);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 1px 6px; border-radius: 5px;
  }}

  .empty {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 40px 28px; text-align: center;
    color: var(--muted); font-size: 14px; line-height: 1.6;
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    box-shadow:
      0 1px 2px rgba(15,15,20,0.04),
      0 12px 32px rgba(15,15,20,0.06),
      inset 0 1px 0 rgba(255,255,255,0.7);
  }}
  .empty-mark {{
    display: inline-flex; align-items: center; justify-content: center;
    width: 44px; height: 44px;
    border-radius: 50%;
    background: rgba(22,163,74,0.10);
    color: #16a34a;
    font-size: 22px; line-height: 1;
    margin-bottom: 14px;
    box-shadow: 0 0 0 6px rgba(22,163,74,0.05);
  }}
  .empty-headline {{
    color: var(--text); font-size: 16px; font-weight: 600;
    letter-spacing: -0.01em; margin-bottom: 6px;
  }}

  /* AI-suggested context — same grid as finding-body, with a labeled divider */
  .rem-divider {{
    margin: 18px 0 12px;
    display: flex; align-items: center; gap: 12px;
    color: var(--muted-2);
    font-size: 10px; font-weight: 600;
    letter-spacing: 0.10em; text-transform: uppercase;
  }}
  .rem-divider::before, .rem-divider::after {{
    content: ""; flex: 1; height: 1px;
    background: var(--border);
  }}
  .rem-divider span {{
    display: inline-flex; align-items: center; gap: 6px;
  }}
  .rem-divider span::before {{
    content: ""; width: 5px; height: 5px; border-radius: 50%;
    background: var(--brand);
    box-shadow: 0 0 0 3px rgba(240,94,0,0.18);
  }}
  .rem-body dd {{
    color: var(--muted);  /* slightly lighter than static fields to mark AI-source */
  }}

  /* CTA */
  .cta {{
    margin: 28px 0 16px;
    background:
      linear-gradient(135deg, rgba(240,94,0,0.08) 0%, rgba(100,90,220,0.04) 100%),
      rgba(255,255,255,0.7);
    border: 1px solid var(--brand-line);
    border-radius: 16px;
    padding: 22px 26px;
    display: flex; align-items: center; justify-content: space-between;
    gap: 18px; flex-wrap: wrap;
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    box-shadow:
      0 2px 4px rgba(15,15,20,0.04),
      0 16px 40px rgba(240,94,0,0.10),
      0 32px 80px rgba(15,15,20,0.06),
      inset 0 1px 0 rgba(255,255,255,0.75);
  }}
  .cta-text {{ flex: 1; min-width: 280px; }}
  .cta-title {{
    font-size: 16px; font-weight: 600; letter-spacing: -0.01em;
    color: var(--text); margin: 0 0 4px;
  }}
  .cta-sub {{
    font-size: 13px; color: var(--muted); line-height: 1.55;
  }}
  .cta-btn {{
    display: inline-flex; align-items: center; gap: 8px;
    background: var(--brand); color: white;
    padding: 11px 20px; border-radius: 11px;
    font-size: 13.5px; font-weight: 600; letter-spacing: 0.01em;
    text-decoration: none;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
    box-shadow:
      0 1px 2px rgba(240,94,0,0.25),
      0 8px 18px rgba(240,94,0,0.22);
  }}
  .cta-btn:hover {{
    transform: translateY(-1px);
    box-shadow:
      0 1px 2px rgba(240,94,0,0.3),
      0 12px 22px rgba(240,94,0,0.28);
  }}

  footer {{
    margin-top: 32px; padding-top: 24px;
    border-top: 1px solid var(--border);
    color: var(--muted); font-size: 12px; line-height: 1.65;
  }}
  footer a {{ color: var(--brand); text-decoration: none; }}
  footer a:hover {{ text-decoration: underline; }}
  footer p {{ color: var(--text-2); }}
  footer p strong {{ color: var(--text); }}

  @media (max-width: 720px) {{
    .vectors {{ grid-template-columns: 1fr; }}
    .hero-row {{ flex-direction: column; align-items: flex-start; }}
    .hero-stat {{ align-items: flex-start; }}
    .finding-body {{ grid-template-columns: 1fr; gap: 2px 0; }}
    .finding-body dt {{ margin-top: 6px; }}
    .hero-title {{ font-size: 26px; }}
    .sev-summary {{ gap: 10px; flex-wrap: wrap; }}
  }}

  /* Toolbar (Print + Download JSON) */
  .toolbar {{
    display: flex; gap: 8px; flex-wrap: wrap;
    margin-bottom: 16px;
  }}
  .toolbar a, .toolbar button {{
    display: inline-flex; align-items: center; gap: 7px;
    background: rgba(255,255,255,0.7);
    border: 1px solid var(--border);
    color: var(--text-2);
    padding: 8px 14px;
    border-radius: 10px;
    font-size: 12.5px; font-weight: 500; letter-spacing: 0;
    text-decoration: none; cursor: pointer;
    font-family: inherit;
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    transition: background 0.15s, border-color 0.15s, transform 0.1s;
    box-shadow:
      0 1px 2px rgba(15,15,20,0.04),
      inset 0 1px 0 rgba(255,255,255,0.7);
  }}
  .toolbar a:hover, .toolbar button:hover {{
    background: var(--brand-soft);
    border-color: var(--brand-line);
    color: var(--brand);
  }}
  .toolbar a:active, .toolbar button:active {{
    transform: translateY(1px);
  }}

  /* Print rules — strip toolbar, CTA, and decorative effects for clean PDFs */
  @media print {{
    html, body {{
      background: white !important;
    }}
    .wrap {{ padding: 16px 0 0; max-width: none; }}
    .toolbar, .cta {{ display: none !important; }}
    .brandbar {{ margin-bottom: 12px; }}
    .hero, .vector-card, .finding, .rem-card, .empty, .sev-pill {{
      background: white !important;
      border-color: #d0d0d0 !important;
      box-shadow: none !important;
      backdrop-filter: none !important;
      -webkit-backdrop-filter: none !important;
    }}
    .finding-body code, .rem-text code {{
      background: #f5f5f5 !important;
      border: 1px solid #e0e0e0;
    }}
    .finding, .vector-card {{
      page-break-inside: avoid;
    }}
    footer {{
      border-top: 1px solid #d0d0d0 !important;
    }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header class="brandbar">
    <div class="brand">
      <span class="brand-mark">CANTINA · SECURITY</span>
      <span class="brand-sub">quickscan · dependency breakdown</span>
    </div>
    <span class="ts">{_esc(ts)}</span>
  </header>

  <div class="toolbar">
    <button type="button" onclick="window.print()">⎙ Print / Save as PDF</button>
    <a href="{json_data_uri}" download="quickscan-breakdown-{download_stamp}.json">⤓ Download JSON</a>
  </div>

  <section class="hero">
    <div class="hero-row">
      <div>
        <h1 class="hero-title">Dependency breakdown</h1>
        <div class="hero-project">{_esc(project)}</div>
      </div>
      <div class="hero-stat">
        <div class="totals"><strong>{total}</strong> {('thing' if total == 1 else 'things')} worth a closer look</div>
        <div class="sev-summary">{sev_summary}</div>
      </div>
    </div>
  </section>

  <h2 class="section">Where we looked</h2>
  <div class="vectors">
    {_vector_card("pip", vectors.get("pip", {}))}
    {_vector_card("vscode", vectors.get("vscode", {}))}
    {_vector_card("mcp", vectors.get("mcp", {}))}
  </div>

  <h2 class="section">What's worth a closer look ({total})</h2>
  {findings_html}

  <div class="cta">
    <div class="cta-text">
      <div class="cta-title">Want to talk through anything you saw here?</div>
      <div class="cta-sub">Quickscan is a heads-up tool — it points at patterns, you decide what to do. If something in this breakdown looks worth a closer conversation, drop us a line. We can help you triage. No commitment.</div>
    </div>
    <a class="cta-btn" href="mailto:{CONTACT_EMAIL}?subject=quickscan%20breakdown" rel="noopener">
      Email us <span>→</span>
    </a>
  </div>

  <footer>
    <p style="margin: 0 0 14px; color: var(--text); font-size: 13px; line-height: 1.6;">
      <strong style="color: var(--brand);">Quickscan is a heads-up tool, not a security audit.</strong>
      It surfaces patterns in your dependencies that may be worth a closer look — it doesn't issue findings,
      verdicts, or audit conclusions. The judgment about whether each pattern is actually a problem is yours.
      For a managed assessment, consider AgentSight.
    </p>
    Generated by <strong style="color:var(--brand);">quickscan</strong> ·
    <a href="https://github.com/aidan269/quickscan">github.com/aidan269/quickscan</a><br>
    Inspired by <a href="https://x.com/DarshanSays/status/2057098732873908503">@DarshanSays · 2026-05-20</a>:
    "Every VS Code extension, pip package, and MCP server is a potential entry point."
  </footer>

</div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("findings_path", help="Path to findings JSON, or '-' for stdin")
    parser.add_argument("--out", help="Output HTML path (default: temp file)", default=None)
    parser.add_argument("--no-open", action="store_true", help="Skip launching the browser")
    args = parser.parse_args()

    if args.findings_path == "-":
        findings = json.load(sys.stdin)
    else:
        findings = json.loads(pathlib.Path(args.findings_path).read_text())

    html_doc = render(findings)

    if args.out:
        out = pathlib.Path(args.out)
    else:
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        out = pathlib.Path(tempfile.gettempdir()) / f"quickscan-breakdown-{stamp}.html"
    out.write_text(html_doc, encoding="utf-8")

    print(str(out))

    if not args.no_open:
        if sys.platform == "darwin":
            subprocess.run(["open", str(out)], check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", str(out)], check=False)
        elif sys.platform == "win32":
            subprocess.run(["cmd", "/c", "start", "", str(out)], check=False, shell=False)


if __name__ == "__main__":
    main()
