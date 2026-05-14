---
name: klaxon-setup
description: Drives the install, configuration, and demo of klaxon — Cantina's self-hosted social monitoring and brand protection tool. Use when a user wants to set up klaxon, demo it to a stakeholder, or monitor a brand for impersonation / mention spikes / keyword anomalies. Asks for brand-specific values one at a time, applies them to socmon.yaml, then runs the deterministic two-pane catch demo so the user sees alerts firing without a real Slack webhook.
---

# klaxon — Cantina's brand monitoring tool

## What klaxon does

A self-hosted social media monitoring and brand protection tool. Code-first
alternative to ZeroFox Social Media Protection and Akamai Brand Guardian.
Detects:

- **Impersonation accounts** mimicking the brand or executives — handle
  similarity (Levenshtein), Cyrillic/Greek homoglyph swaps, avatar
  perceptual-hash distance against configured brand logos, account age,
  brand keyword presence in handle and bio. Exec impersonations auto-promote
  to critical severity.
- **Mention spikes** — rolling baseline of brand mentions across collectors;
  z-score anomaly detection on the most recent bucket, with a min-volume
  floor to avoid noise on near-zero baselines.
- **Keyword spikes** — same anomaly math per configured `Keyword`, with a
  small left-to-right boolean DSL (`AND`/`OR`/`NOT`/`"phrases"`/`NEAR/N`).

Alerts route to Slack (Block Kit), PagerDuty (Events API v2), generic
HMAC-signed webhooks, or any local receiver. Detection only — there's
deliberately no automated takedown / remediation pipeline.

Source: https://github.com/aidan269/klaxon

## When to use this skill

A Cantina security engineer or auditor asks any of:
- "Set up klaxon for me"
- "Demo klaxon to <person>"
- "Help me monitor <brand> for impersonation"
- "Run the klaxon brand-monitoring demo"
- "Configure klaxon's keyword tracking for <topic>"

The skill is interactive: it asks for brand-specific input one question at
a time and applies each answer to the live `socmon.yaml`. Stop and wait
when input is needed. Do not invent placeholder brand names — ask.

## Setup walkthrough

### 1. Locate or clone klaxon

If the user is already in a klaxon checkout, `git pull origin main`.
Otherwise:

```bash
git clone https://github.com/aidan269/klaxon.git
cd klaxon
```

### 2. Verify Python 3.11+

```bash
python3.11 --version || brew install python@3.11   # macOS
# Linux: use the system package manager
```

### 3. Create venv and install

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev,slack]"
.venv/bin/pytest -q   # confirm 139+ tests pass before continuing
```

### 4. Generate the starter config

```bash
.venv/bin/socmon init       # writes socmon.yaml from the example template
```

### 5. Fill the config — ONE QUESTION AT A TIME

Open `socmon.yaml`. Replace the example "Acme" values by asking the user
for each field below and applying each answer to the file:

- **organization name** (free text — e.g. "Spearbit", "Cantina")
- **brand name and aliases** — the canonical brand plus how it shows up in
  the wild (logos, casual references, alternate spellings)
- **corporate domains** — used for typosquat detection on job postings
- **legitimate brand handles per platform** — `reddit`, `twitter`,
  `bluesky`, `mastodon`, etc. These are the *exclude* list; anything that
  resembles them but isn't on the list becomes an impersonation candidate
- **executives to monitor** — name, title, their legitimate handles per
  platform. Mark `high_value_target: true` for execs whose impersonations
  should auto-promote to CRITICAL
- **keywords to track** — boolean expressions per `Keyword` config, each
  with a severity floor. Examples:
    - `'"acme" AND breach'` (severity: high)
    - `'"acme" NEAR/10 credentials'` (severity: high)
    - `'acmecorp'` (severity: low)
  The DSL is strict left-to-right: no parens, no precedence. Use multiple
  `Keyword` entries for OR-of-AND patterns
- **brand logo image paths** — local files used for avatar pHash matching
  against impersonation candidates' avatars

Skip optional sections the user explicitly says they don't need.

### 6. (Optional) Slack alerting

If the user wants live Slack alerts during the demo or in production:

```bash
export SOCMON_SLACK_BRAND_WEBHOOK=<webhook-url>
.venv/bin/socmon alerts test --channel slack-brand   # one synthetic finding
```

Tell the user to check their Slack channel for the test message before
proceeding to the real demo.

### 7. The recommended demo — two-pane catch flow

This is the demo for content recordings, manager walkthroughs, and "show
me it working" sessions. It uses a local HTTP receiver instead of Slack
so nothing ends up in a real workspace.

Open a second terminal pane. In pane 1, start the receiver:

```bash
.venv/bin/python examples/catch.py     # listens on http://127.0.0.1:8765/
```

In pane 2, fire klaxon at it:

```bash
clear
.venv/bin/socmon demo --watch --findings-only --catch --interval-seconds 5 2>/dev/null
```

What the user sees:

- **Pane 2 (klaxon)**: an initial block of 7 findings appears immediately
  — three impersonations (HIGH typosquat, HIGH homoglyph, CRITICAL exec),
  one CRITICAL mention spike (z≈234), and three CRITICAL keyword spikes.
  Then every 5 seconds, one fresh impersonation candidate is seeded and
  a new finding line scrolls in.
- **Pane 1 (catcher)**: each finding lands as a colored severity line
  the moment klaxon fires it — red CRITICAL, orange HIGH, yellow MEDIUM,
  gray LOW. Each line shows the title, score, evidence URL, and the
  HMAC signature prefix when signing is configured.

Ctrl-C in either pane to stop. After Ctrl-C in the klaxon pane, output
ends with `Stopped after N drip(s).`

### 8. Real scan (optional)

To prove klaxon works against actual upstream platforms (not just
fixtures), point it at Reddit and the configured RSS feeds:

```bash
.venv/bin/socmon scan --window-hours 168 --findings-only
```

This is non-deterministic. For a fictitious brand like "Acme" the scan
will collect real Reddit chatter and RSS articles but typically produce
zero findings; that's correct behavior. For a real customer brand,
expect actual hits.

### 9. Continuous mode for production

```bash
.venv/bin/socmon run
```

APScheduler-backed long-running process. Each enabled collector ticks on
its own `poll_interval_seconds`; detectors tick together every
`detector_interval_seconds` (default 300). Ctrl-C / SIGTERM drains
in-flight jobs and exits cleanly. Pair with systemd/launchd for
restart-on-crash supervision.

For ad-hoc scheduled runs, cron with `socmon scan` is also supported and
robust to memory leaks since each tick is a fresh process.

## CLI surface reference

| Subcommand | Purpose |
|------------|---------|
| `socmon init` | Write starter `socmon.yaml` from the example template |
| `socmon scan` | One-shot collect + detect + alert (good under cron) |
| `socmon run` | Long-running scheduler (Ctrl-C / SIGTERM to stop) |
| `socmon backtest` | Replay detectors over already-collected observations |
| `socmon demo` | Deterministic fixture demo (no network calls by default) |
| `socmon demo --watch --catch` | Continuous drip demo to a local receiver |
| `socmon prune --older-than-days N` | Delete observations + findings older than N days |
| `socmon alerts test` | Fire a synthetic finding through every configured alerter |

Useful flags:
- `--findings-only` (on `scan` / `demo`): suppress Accounts and Posts
  sections for screen-share-ready output
- `--catch [URL]` (on `demo`): route findings to a local webhook receiver
  instead of configured alerters; defaults to `http://127.0.0.1:8765/`
- `--alerts` (on `demo`): route findings to the configured Slack /
  PagerDuty / webhook alerters. Requires `--yes` or interactive
  confirmation
- `--detector-interval-seconds N` (on `run`): override the global detector
  cadence for one run

## What klaxon remembers between runs

State persists in SQLite (dev) or Postgres (prod). Four tables:

- `observations` — every account/post ever ingested, keyed by stable
  platform id. Re-collecting is idempotent
- `findings` — every alert ever fired, keyed by a deterministic id
  (detector + entity + bucket). Same finding can't re-alert across
  restarts
- `watermarks` — per-collector "latest created_at successfully ingested,"
  so each tick only fetches what's new
- `kv_state` — generic detector state. The impersonation detector uses
  it to hash each scored account; unchanged accounts skip rescoring on
  the next tick

Rolling baselines for the spike detectors and brand-logo perceptual
hashes are recomputed each run — they're not persisted. That's what
makes `socmon backtest` reproducible: replaying detectors over the same
observations always produces the same findings.

## Configuration philosophy

- One YAML file (`socmon.yaml`) describes everything
- Credentials are referenced by env-var name only (e.g.
  `webhook_url_env: SOCMON_SLACK_BRAND_WEBHOOK`). Secrets never live in
  the YAML
- Adding a platform = one new file implementing the `Collector` interface,
  registered with `@register("<platform-name>")`. No other code changes
- Adding a detector signal = one new file implementing `Detector`
- Adding a notification channel = one new file implementing `Alerter`

## Cadence guidance

| Cadence  | Status                   | Notes                                                          |
|----------|--------------------------|----------------------------------------------------------------|
| ≥ 5 min  | Production sweet spot    | Well under Reddit's anonymous ~60 req/min limit                |
| 1–4 min  | Demo / incident-response | Reddit holds; some RSS feeds will start 429ing on tight cycles |
| < 1 min  | Only via launchd/systemd | cron's floor is 1 min; expect upstream rate-limit degradation  |

klaxon is dedup-safe at any cadence — watermarks prevent re-ingestion and
findings are keyed on deterministic ids, so an over-aggressive cron only
burns upstream API quota; it never produces duplicate alerts.

## References

- Source repo: https://github.com/aidan269/klaxon
- Quick-start documentation: README in the repo
- Two-pane catch demo: `examples/catch.py` in the repo
- Architecture: collectors / detectors / alerters as pluggable interfaces;
  storage is SQLAlchemy 2.0 against SQLite or Postgres
