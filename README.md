# SecurityAlertAutomation

Monitors SOC alert emails, extracts the attacker Origin IP, and automatically
appends it to the **source network list** of an existing Sophos SFOS firewall
rule — causing the firewall to immediately reject all traffic from that IP.

A built-in web dashboard (started automatically by the same process) gives
administrators live visibility into everything the automation does: alert
history, firewall actions, structured logs, KPIs, and an allow-list editor —
with no separate frontend server or build step required.

---

## Features

- **Email monitoring** — polls a mailbox over IMAP, filters by trusted sender
  and alert keyword, and extracts the attacker IP from the SOC alert HTML.
- **Automatic firewall blocking** — appends the IP to an existing Sophos SFOS
  firewall rule via its XML API. Duplicates and allow-listed IPs are skipped.
- **Automatic retry on failure** — if a firewall update fails (API error,
  connectivity issue, etc.), the IP is queued and retried on every
  subsequent cycle until it succeeds — no manual intervention needed.
- **Email notifications** — sends a single notification on block success or
  failure to a configured recipient/distribution list.
- **Integrated web dashboard** — SOC-style dashboard with live KPIs, charts,
  a live activity feed (via Server-Sent Events), searchable/filterable/
  paginated tables for alerts/firewall actions/logs, CSV/Excel export, an
  allow-list editor, and a settings page that writes safely back to `.env`.
- **Firewall connectivity monitor** — pings the firewall on its own interval
  and shows live status (online/unreachable) in the dashboard, with a
  click-to-test button.
- **Structured logging** — every event is logged to file, to SQLite, and
  streamed live to the dashboard, with credentials automatically redacted.

---

## How it works

```
SOC alert email received
        │
        ▼
Sender verified against TRUSTED_SENDERS
        │ trusted?
        ▼
Origin IP extracted from alert HTML
        │
        ▼
IP checked against config/allowed_ips.txt (or the Allowed IPs dashboard page)
        │ not whitelisted?
        ▼
Fetch firewall rule (FIREWALL_RULE_NAME) from SFOS
        │
        ▼
IP already in rule? ──YES──► log "already blocked", stop
        │ NO
        ▼
Append IP to SourceNetworks list
        │
        ▼
Validate XML
        │
        ▼
Upload updated rule to SFOS
        │
        ├── success ──► notify + record "blocked"; KPIs/charts update
        │
        └── failure ──► notify + record "failed"; IP is queued for
                         automatic retry on every following cycle until
                         it succeeds (then KPIs/charts update to reflect it)
```

---

## Setup guide (step by step)

### Automatic Windows setup

Double-click `setup.bat` from the project directory. It detects Python 3.10 or newer, creates or reuses `.venv`, installs the required packages, prepares runtime folders, and creates `.env` from `.env.example` only when `.env` is missing. Existing credentials are never overwritten.

If a new `.env` is created, setup opens it in Notepad so you can enter the required IMAP, SMTP, firewall, and dashboard settings. After saving it, double-click `run_firewall.bat` to start the application.

The manual commands below perform the same core setup steps.

These commands assume **Windows PowerShell** and Python 3.10+ already
installed. Run them from the project root.

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

This installs both the backend dependencies (requests, BeautifulSoup,
python-dotenv) and the dashboard dependencies (FastAPI, uvicorn, Jinja2,
openpyxl).

### 3. Create your configuration file

```powershell
Copy-Item .env.example .env
```

Open `.env` in an editor and fill in every value under **Sophos SFOS
firewall**, **Email / IMAP**, **SMTP**, and **Alert filtering** (see
[Configuration](#configuration) below for what each variable means). Leave
the **Database**, **Dashboard**, and firewall ping interval sections at
their defaults unless you have a specific reason to change them — they can
also be edited later from the dashboard's Settings page (except database
path and log directory, which stay file-only).

### 4. Prepare the firewall rule

In the SFOS GUI:

1. Create (or verify) a firewall rule whose **Action** is **Reject**.
2. Note its exact name (e.g. `Block IP`).
3. Set `FIREWALL_RULE_NAME=Block IP` in `.env` to match exactly (case-sensitive).

### 5. Set your allowed IPs (optional but recommended)

Edit `config/allowed_ips.txt` to list any IPs that must never be blocked
(internal infrastructure, monitoring tools, etc.) — one per line. You can
also manage this list from the dashboard's **Allowed IPs** page after first
launch.

### 6. Run it

```powershell
python main.py
```

That single command:

1. Runs one bounded, status-aware email catch-up scan covering recent read and unread mail.
2. Starts the normal live email monitor and existing firewall retry processing.
3. Starts the firewall connectivity monitor in the background.
3. Starts the web dashboard.
4. Opens your default browser to the dashboard automatically.

No second terminal, no `npm run`, no separate frontend process.

### 7. Sign in (if you set an admin password)

If `DASHBOARD_ADMIN_PASSWORD` is set in `.env`, you'll land on a login page
first. Use `DASHBOARD_ADMIN_USERNAME` / `DASHBOARD_ADMIN_PASSWORD`. Leaving
the password blank disables login entirely (fine for a trusted local
machine only).

### 8. Verify it's working

- The **Dashboard** page should show live KPIs (all zero on a fresh install)
  and a "Firewall: online" pill in the top-right if the firewall is
  reachable.
- Check `logs/application.log` (or the **Logs** page) for clean operational
  events such as `Configuration loaded` and `Application services started`.

---

## Configuration

All configuration lives in `.env` (copied from `.env.example`). Fields
marked "Settings page" can also be edited from the dashboard without
touching the file directly.

```
# Sophos SFOS firewall
FIREWALL_HOST=192.168.20.210
FIREWALL_PORT=20792
FIREWALL_USERNAME=admin
FIREWALL_PASSWORD=your_password
FIREWALL_RULE_NAME=Block IP
FIREWALL_PING_INTERVAL=60

# IMAP (inbound alert polling) — Microsoft 365 / Outlook example
IMAP_HOST=outlook.office365.com
IMAP_PORT=993
IMAP_USE_SSL=true
IMAP_USE_STARTTLS=false
IMAP_MAILBOX=INBOX
IMAP_FOLDERS=INBOX
IMAP_UID_RECONCILE_COUNT=20
EMAIL_USERNAME=monitor@company.com
EMAIL_PASSWORD=your_password

# SMTP (outbound notifications) — Microsoft 365 / Outlook example
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USE_SSL=false

# Notification recipient
NOTIFICATION_EMAIL=security-alerts@company.com

# Alert filtering
TRUSTED_SENDERS=soc@centurypaper.com.pk, alerts@centurypaper.com.pk
ALERT_KEYWORDS=attack

# Allowed IPs
ALLOWED_IPS_FILE=config/allowed_ips.txt

# Logging
LOG_DIRECTORY=logs/
LOG_LEVEL=INFO
DEBUG_LOGGING=false
DEBUG_LOG_MAX_CHARS=2000

# Polling
IMAP_POLL_INTERVAL=60
IMAP_RUN_LOOP=true
EMAIL_LOOKBACK_HOURS=24
EMAIL_LOOKBACK_MAX_MESSAGES=200

# Database
DATABASE_PATH=data/app.db

# Dashboard
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=8765
DASHBOARD_AUTO_OPEN_BROWSER=true
DASHBOARD_ADMIN_USERNAME=admin
DASHBOARD_ADMIN_PASSWORD=
```

### Key settings explained

| Variable | Description | Settings page |
| --- | --- | --- |
| `FIREWALL_HOST` / `FIREWALL_PORT` | SFOS management IP/hostname and XML API port | ✓ |
| `FIREWALL_USERNAME` / `FIREWALL_PASSWORD` | SFOS API credentials | ✓ |
| `FIREWALL_RULE_NAME` | Exact name of the existing SFOS rule to update (e.g. `Block IP`) | ✓ |
| `FIREWALL_PING_INTERVAL` | Seconds between firewall connectivity checks (independent of `IMAP_POLL_INTERVAL`) | ✓ |
| `IMAP_HOST` / `IMAP_PORT` | IMAP server for polling SOC alerts | ✓ |
| `IMAP_USE_SSL` | `true` for implicit SSL (port 993 — Outlook/Gmail); `false` for plain IMAP | ✓ |
| `EMAIL_USERNAME` / `EMAIL_PASSWORD` | Mailbox credentials used to read alerts | ✓ |
| `IMAP_POLL_INTERVAL` | Seconds between IMAP polls (default: 60) | ✓ |
| `IMAP_FOLDERS` | Comma-separated folders monitored by durable UID checkpoints (default: INBOX) | file only |
| `IMAP_UID_RECONCILE_COUNT` | Recent UIDs rechecked after startup or reconnect (default: 20) | file only |
| `EMAIL_LOOKBACK_HOURS` | Startup catch-up window in hours; invalid values fall back to 24 | file only |
| `EMAIL_LOOKBACK_MAX_MESSAGES` | Maximum trusted messages examined during startup; invalid values fall back to 200 | file only |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for sending notifications | ✓ |
| `SMTP_USE_TLS` | `true` for STARTTLS (port 587 — Outlook); mutually exclusive with `SMTP_USE_SSL` | ✓ |
| `SMTP_USE_SSL` | `true` for implicit SSL (port 465) | ✓ |
| `NOTIFICATION_EMAIL` | Single recipient for block/failure notifications (shared mailbox or distro list) | ✓ |
| `SMTP_FROM` | Optional From address (defaults to `EMAIL_USERNAME`); use for shared mailbox send-as | ✓ |
| `TRUSTED_SENDERS` | Comma-separated list of sender addresses; an email is processed if it matches any of them (case-insensitive). Legacy singular `TRUSTED_SENDER` is still accepted if this is unset | ✓ |
| `ALERT_KEYWORDS` | Comma-separated keywords; the alert's classification must match at least one | ✓ |
| `ALLOWED_IPS_FILE` | Path to the allowed-IP file (also editable from the Allowed IPs page) | file only |
| `IMAP_RUN_LOOP` | `true` = poll continuously; `false` = run one cycle then exit | file only |
| `LOG_DIRECTORY` / `LOG_LEVEL` | Production log directory and minimum operational level | file only |
| `DEBUG_LOGGING` | Write redacted technical diagnostics to `debug.log` (default: false) | file only |
| `DEBUG_LOG_MAX_CHARS` | Maximum technical payload length before truncation (default: 2000) | file only |
| `DATABASE_PATH` | SQLite database file location (alerts, firewall actions, logs, stats) | file only |
| `DASHBOARD_HOST` / `DASHBOARD_PORT` | Where the dashboard listens | ✓ |
| `DASHBOARD_AUTO_OPEN_BROWSER` | Open the default browser automatically on startup | ✓ |
| `DASHBOARD_ADMIN_USERNAME` / `DASHBOARD_ADMIN_PASSWORD` | Dashboard login; leave password blank to disable auth | ✓ |

Settings-page edits take effect **after restarting** `python main.py`.

---

## Email provider configuration

The application uses standard **IMAP** (inbound) and **SMTP** (outbound). No
provider is hardcoded — only `.env` controls which mail system is used.

### Microsoft 365 / Outlook (recommended)

```
IMAP_HOST=outlook.office365.com
IMAP_PORT=993
IMAP_USE_SSL=true
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USE_TLS=true
EMAIL_USERNAME=monitor@company.com
EMAIL_PASSWORD=<app password or service account password>
NOTIFICATION_EMAIL=security-alerts@company.com
```

**Notification recipient:** Set `NOTIFICATION_EMAIL` to the Outlook shared
mailbox or distribution list IT manages. The application sends **one
email** to that address; IT forwarding rules deliver it to the security
team. Do not list individual recipients in code or `.env`.

**Shared mailbox send-as:** If notifications must appear from a shared
mailbox address, set `SMTP_FROM` to that address (the authenticated account
must have send-as permission).

### Switching providers

To use Gmail or another provider, change only the host/port/TLS values:

| Provider | IMAP host | IMAP port | SMTP host | SMTP port | TLS |
|----------|-----------|-----------|-----------|-----------|-----|
| Microsoft 365 | `outlook.office365.com` | 993 | `smtp.office365.com` | 587 | STARTTLS |
| Gmail | `imap.gmail.com` | 993 | `smtp.gmail.com` | 587 | STARTTLS |

---

## Allowed IP list

Manage this list either by editing `config/allowed_ips.txt` directly, or
from the dashboard's **Allowed IPs** page (adds/removes write straight back
to the same file — they stay in sync either way).

```
# Internal infrastructure -- never block
192.168.1.10
10.0.0.5
172.16.20.50
```

When an alert's origin IP matches this list, the system logs
`IP is whitelisted` and takes no further action — no XML is modified, no
upload is performed.

---

## Firewall rule prerequisite

The automation targets an **existing** rule in SFOS — it does not create
one. Before running:

1. In the SFOS GUI, create (or verify) a firewall rule whose **Action** is **Reject**.
2. Note the exact rule name (e.g. `Block IP`).
3. Set `FIREWALL_RULE_NAME=Block IP` in `.env`.

The rule's source-network list is updated automatically. All existing
entries are preserved; only the new IP is appended (never duplicated).

---

## Automatic retry for failed blocks

If a firewall update fails for any reason (timeout, API error, rule not
found, etc.):

1. The alert is recorded with `action_taken=failed` and a failure
   notification is sent.
2. The IP is placed in a retry queue.
3. On **every** subsequent polling cycle, the queued IP is retried before
   any new mail is processed — indefinitely, until the firewall accepts it.
4. Once it succeeds, the original alert is updated to reflect the new
   outcome (`blocked`/`duplicate`/`allowed`), a success notification is
   sent, and the **Failed Blocks** KPI, the **Action Breakdown** chart, and
   the **Alert Volume** chart on the dashboard all update to match —
   nothing needs to be reprocessed manually.

---

## The dashboard

Once running, the dashboard is available at
`http://<DASHBOARD_HOST>:<DASHBOARD_PORT>` (defaults to
`http://127.0.0.1:5000`) and includes:

| Page | What it shows |
| --- | --- |
| **Dashboard** | Live KPI cards, a 14-day alert volume chart, an action-breakdown chart, and a real-time activity feed (via SSE). Double-clicking a KPI or a chart bar drills into the Alert History page pre-filtered. |
| **Alert History** | Every processed SOC email — searchable, filterable, sortable, paginated, exportable to CSV/Excel, with a "Clear All" option. |
| **Firewall Actions** | Every firewall rule update attempt (blocked/duplicate/allowed/failed) with the same search/filter/export/clear tooling. |
| **Allowed IPs** | Add/remove IPs from the allow list; changes write directly to `config/allowed_ips.txt`. |
| **Logs** | Structured application logs with severity/module/date/keyword filters, auto-refresh, and export. |
| **Settings** | Edit most `.env` values through a form (secrets are masked) instead of hand-editing the file. |

The firewall connectivity pill in the top bar shows green when the firewall
API is reachable and red when it isn't; click it any time to force an
immediate connectivity test.

---

## Running

```powershell
.\.venv\Scripts\Activate.ps1
python main.py
```

Set `IMAP_RUN_LOOP=true` for continuous monitoring (default), or
`IMAP_RUN_LOOP=false` to process the current inbox once and exit — note the
dashboard still runs continuously in this mode since it's a separate
service within the same process.

---

## Running tests

```powershell
.\.venv\Scripts\Activate.ps1
pytest -q
```

All tests pass with no external connections required (IMAP/SMTP/firewall
calls are mocked).

---

## Project architecture

```
SecurityAlertAutomation/
│
├── core/                          # Backend application logic
│   ├── config.py                  # Load & validate .env into AppConfig
│   ├── logger.py                  # Console + rotating file + SQLite/live logging
│   ├── event_translator.py        # Raw log lines → human-readable SOC events
│   ├── event_bus.py               # In-process pub/sub for the live activity feed (SSE)
│   ├── database.py                # SQLite schema, stats, queries, retry queue
│   ├── env_file.py                # Structure-preserving .env reader/writer
│   ├── allowed_ips_file.py        # Read/add/remove entries in allowed_ips.txt
│   ├── firewall_client.py         # Sophos SFOS XML API (get/set rule, connectivity ping)
│   ├── firewall_status.py         # Thread-safe cache of the last connectivity check
│   ├── firewall_monitor.py        # Background loop: pings the firewall on its own interval
│   ├── xml_handler.py             # Parse, mutate, validate rule XML
│   ├── rule_updater.py            # Orchestrates the full block-IP flow
│   ├── email_client.py            # Provider-agnostic IMAP/SMTP transport
│   └── email_monitor.py           # IMAP polling, alert parsing, retry queue, notifications
│
├── web/                           # Integrated dashboard (FastAPI + Jinja2 + vanilla JS)
│   ├── app.py                     # FastAPI app factory, sessions, static file serving
│   ├── auth.py                    # Optional admin login (session-based)
│   ├── routes/
│   │   ├── pages.py                # Server-rendered dashboard pages
│   │   ├── api.py                  # JSON API: stats, alerts, firewall actions, logs, SSE
│   │   ├── export.py               # CSV/Excel export endpoints
│   │   └── allowed_ips.py          # Allowed-IP page + API
│   ├── services/
│   │   ├── settings_service.py     # Settings-page ↔ .env mapping
│   │   └── export_service.py       # CSV/Excel generation
│   ├── templates/                  # Jinja2 templates (one per page + shared base layout)
│   └── static/                     # CSS, vanilla JS, logo
│
├── config/
│   └── allowed_ips.txt            # IPs that must never be blocked
│
├── tests/                         # Backend unit tests (mocked I/O, no network required)
│
├── main.py                        # Entry point: starts monitor threads + dashboard
├── conftest.py                    # pytest path configuration
├── .env                           # Secrets (not committed)
├── .env.example                   # Template for .env
└── requirements.txt
```

Each backend module has exactly one responsibility. The web layer reuses
`core/` modules directly (e.g. reading the same SQLite database and
`allowed_ips.txt` the backend writes) rather than duplicating logic.

---

## Security notes

- Firewall API credentials are **never** written to logs — request/response
  bodies are redacted before logging, even in SFOS's per-request auth mode
  where credentials are embedded in every API call.
- The dashboard session secret is persisted to disk (next to the database)
  so restarting `python main.py` doesn't log everyone out or drop in-flight
  filtered views.
- Dashboard login is optional; leaving `DASHBOARD_ADMIN_PASSWORD` blank
  disables it — only do this on a trusted local machine.
- Settings-page password fields are masked in the browser and never
  round-tripped in plaintext unless explicitly changed.

---

## Troubleshooting

### Email / firewall processing

| Symptom | Cause | Fix |
| --- | --- | --- |
| Log: `sender ... is not trusted` | Email is from an address not in the trusted list | Check `TRUSTED_SENDERS` in `.env` |
| Log: `classification ... does not match ALERT_KEYWORDS` | Alert text doesn't contain a configured keyword | Check `ALERT_KEYWORDS`, or leave broad |
| Log: `IP ... is whitelisted` | IP is in `allowed_ips.txt` | Remove it from the Allowed IPs page/file if blocking is intended |
| Log: `IP ... already blocked` | IP is already in the rule | No action needed |
| Log: `Rule ... not found` | `FIREWALL_RULE_NAME` mismatch | Copy the rule name exactly from the SFOS GUI |
| Log: `Authentication failed` | Wrong firewall credentials | Fix `FIREWALL_USERNAME`/`FIREWALL_PASSWORD` |
| Log: `Retry failed for ...` | Firewall still unreachable/rejecting | Check firewall connectivity; the IP retries automatically every cycle |
| `IMAP authentication failed` | Wrong credentials or IMAP disabled | Verify `EMAIL_USERNAME`/`EMAIL_PASSWORD`; ensure IMAP is enabled |
| `SMTP authentication failed` | Wrong credentials or SMTP AUTH disabled | Verify SMTP AUTH is enabled; use an app password if MFA is on |
| Notification appears in inbox as an unread alert | `TRUSTED_SENDERS` matches the notification's From address | Set `SMTP_FROM` to an address not listed in `TRUSTED_SENDERS` |

### Dashboard

| Symptom | Cause | Fix |
| --- | --- | --- |
| `only one usage of each socket address` on startup | Another instance is already running on that port | Stop the other process, or change `DASHBOARD_PORT` |
| Redirected to a blank/unfiltered page after login | Session expired mid-navigation | Sessions now persist across restarts; if this recurs, check that `data/.session_secret` is writable |
| Changes to CSS/JS don't show up | Browser cached the old static file | Hard refresh (Ctrl+Shift+R) the affected page |
| "Firewall: unreachable" pill | Firewall API unreachable or credentials wrong | Click the pill to re-test; check `FIREWALL_HOST`/`FIREWALL_PORT`/credentials |

### Checking the log

```powershell
Get-Content logs\application.log -Tail 50
```

Errors with diagnostic stack traces are written to `logs/error.log`. When
`DEBUG_LOGGING=true`, redacted and truncated protocol details are isolated in
`logs/debug.log`. Or use the **Logs** page for live, filterable, exportable
structured logs.

### Verifying the rule in SFOS GUI

1. **Rules and policies → Firewall rules** — open the configured rule.
2. Under **Source → Source networks**, the new IP should appear.
3. **Logs → Firewall log** — filter by the blocked IP to confirm traffic is
   being rejected.
