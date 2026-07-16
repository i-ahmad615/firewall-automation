# SecurityAlertAutomation

Monitors SOC alert emails, extracts the attacker Origin IP, and automatically
appends it to the **source network list** of an existing Sophos SFOS firewall
rule — causing the firewall to immediately reject all traffic from that IP.

---

## How it works

```
SOC alert email received
        │
        ▼
Sender verified against TRUSTED_SENDER
        │ trusted?
        ▼
Origin IP extracted from alert HTML
        │
        ▼
IP checked against config/allowed_ips.txt
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
        ▼
Firewall immediately rejects all traffic from that IP
```



---



## Configuration

Copy `.env.example` to `.env` and fill in every value.

```
# Sophos SFOS firewall
FIREWALL_HOST=192.168.20.210
FIREWALL_PORT=20792
FIREWALL_USERNAME=admin
FIREWALL_PASSWORD=your_password

# Must match the exact rule name in SFOS (case-sensitive)
FIREWALL_RULE_NAME=Block IP

# IMAP (inbound alert polling) — Microsoft 365 / Outlook example
IMAP_HOST=outlook.office365.com
IMAP_PORT=993
IMAP_USE_SSL=true
IMAP_USE_STARTTLS=false
IMAP_MAILBOX=INBOX
EMAIL_USERNAME=monitor@company.com
EMAIL_PASSWORD=your_password

# SMTP (outbound notifications) — Microsoft 365 / Outlook example
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USE_SSL=false

# Single notification recipient (shared mailbox or distribution list)
NOTIFICATION_EMAIL=security-alerts@company.com

# Alert filtering
TRUSTED_SENDER=soc@centurypaper.com.pk
ALERT_KEYWORDS=attack

# Allowed IPs (IPs that must never be blocked)
ALLOWED_IPS_FILE=config/allowed_ips.txt

# Logging
LOG_DIRECTORY=logs/
LOG_LEVEL=INFO

# Polling
IMAP_POLL_INTERVAL=60
IMAP_RUN_LOOP=true
```



### Key settings explained


| Variable             | Description                                                                          |
| -------------------- | ------------------------------------------------------------------------------------ |
| `FIREWALL_RULE_NAME` | Exact name of the existing SFOS rule to update (e.g. `Block IP`)                     |
| `IMAP_HOST` / `IMAP_PORT` | IMAP server for polling SOC alerts (provider-specific — set in `.env` only)   |
| `IMAP_USE_SSL`       | `true` for implicit SSL (port 993 — Outlook/Gmail); `false` for plain IMAP         |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for sending notifications (provider-specific — set in `.env` only) |
| `SMTP_USE_TLS`       | `true` for STARTTLS (port 587 — Outlook); `false` when using `SMTP_USE_SSL`          |
| `SMTP_USE_SSL`       | `true` for implicit SSL (port 465); cannot be used with `SMTP_USE_TLS=true`          |
| `NOTIFICATION_EMAIL` | Single recipient for block/failure notifications (shared mailbox or distro list)   |
| `SMTP_FROM`          | Optional From address (defaults to `EMAIL_USERNAME`; use for shared mailbox send-as) |
| `TRUSTED_SENDER`     | Only emails from this address are processed (case-insensitive)                       |
| `ALERT_KEYWORDS`     | Comma-separated keywords; email must match at least one (leave blank to process all) |
| `ALLOWED_IPS_FILE`   | Path to the allowed-IP whitelist file                                                |
| `IMAP_RUN_LOOP`      | `true` = poll continuously; `false` = run one cycle then exit                        |
| `IMAP_POLL_INTERVAL` | Seconds to wait between IMAP polls (default: 60)                                     |


---

## Email provider configuration

The application uses standard **IMAP** (inbound) and **SMTP** (outbound). No provider is
hardcoded in the Python source — only `.env` controls which mail system is used.

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

**Notification recipient:** Set `NOTIFICATION_EMAIL` to the Outlook shared mailbox or
distribution list IT manages. The application sends **one email** to that address;
IT forwarding rules deliver it to the security team. Do not list individual recipients
in code or `.env`.

**Shared mailbox send-as:** If notifications must appear from a shared mailbox address,
set `SMTP_FROM` to that address (the authenticated account must have send-as permission).

### Switching providers

To use Gmail or another provider, change only the host/port/TLS values in `.env`:

| Provider | IMAP host | IMAP port | SMTP host | SMTP port | TLS |
|----------|-----------|-----------|-----------|-----------|-----|
| Microsoft 365 | `outlook.office365.com` | 993 | `smtp.office365.com` | 587 | STARTTLS |
| Gmail | `imap.gmail.com` | 993 | `smtp.gmail.com` | 587 | STARTTLS |

---

## Allowed IP list

Edit `config/allowed_ips.txt` to list IPs that must **never** be blocked.
One IP per line. Lines beginning with `#` are comments.

```
# Internal infrastructure -- never block
192.168.1.10
10.0.0.5
172.16.20.50
```

When an alert IP matches this list, the system logs `IP is whitelisted` and
takes no further action. No XML is modified, no upload is performed.

---



## Firewall rule

The automation targets an existing rule in SFOS. Before running:

1. In the SFOS GUI create (or verify) a firewall rule whose **Action** is **Reject**.
2. Note the exact rule name (e.g. `Block IP`).
3. Set `FIREWALL_RULE_NAME=Block IP` in `.env`.

The rule's source-network list will be updated automatically. All existing
entries are preserved; only the new IP is appended (never duplicated).

---



## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your values
```

---



## Running

```powershell
.\.venv\Scripts\Activate.ps1
python main.py
```

Set `IMAP_RUN_LOOP=true` for continuous monitoring.
Set `IMAP_RUN_LOOP=false` to process the current inbox once and exit.

---



## Running tests

```powershell
.\.venv\Scripts\Activate.ps1
pytest -q
```

All tests should pass with no external connections required.

### Email troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `IMAP authentication failed` | Wrong credentials or IMAP disabled | Verify `EMAIL_USERNAME`/`EMAIL_PASSWORD`; ensure IMAP is enabled in M365 admin |
| `SMTP authentication failed` | Wrong credentials or SMTP AUTH disabled | Verify SMTP AUTH is enabled; use app password if MFA is on |
| `IMAP connection failed` | Wrong host/port or firewall block | Confirm `IMAP_HOST`/`IMAP_PORT` and outbound access to port 993 |
| `Notification not sent` | SMTP misconfiguration | Check `SMTP_HOST`, `SMTP_USE_TLS`, and `NOTIFICATION_EMAIL` in logs |
| Notification appears in inbox as unread alert | `TRUSTED_SENDER` matches notification From | Set `SMTP_FROM` to a different address than `TRUSTED_SENDER` |

---



## Project architecture

```
SecurityAlertAutomation/
│
├── core/                        # All application logic
│   ├── config.py                # Load & validate .env into AppConfig
│   ├── logger.py                # UTF-8 console + rotating file logger
│   ├── firewall_client.py       # Sophos SFOS XML API (get/set rule)
│   ├── xml_handler.py           # Parse, mutate, validate rule XML
│   ├── rule_updater.py          # Orchestrates the full block-IP flow
│   ├── email_client.py          # Provider-agnostic IMAP/SMTP transport
│   ├── email_monitor.py         # IMAP polling + alert parsing + notifications
│
├── config/
│   └── allowed_ips.txt          # IPs that must never be blocked
│
├── tests/
│   ├── test_config.py           # Config loading and allowed-IP logic
│   ├── test_xml_handler.py      # XML parsing and mutation
│   ├── test_rule_updater.py     # End-to-end block flow (mocked)
│   ├── test_email_client.py     # IMAP/SMTP transport (mocked)
│   ├── test_email_monitor.py    # Email parsing and sender filtering
│   └── test_firewall_client.py  # SFOS API client (mocked HTTP)
│
├── main.py                      # Entry point
├── conftest.py                  # pytest path configuration
├── .env                         # Secrets (not committed)
├── .env.example                 # Template for .env
└── requirements.txt
```

Each module has exactly one responsibility. No module imports from another
module at the same level except through `rule_updater.py` (which wires
`firewall_client` + `xml_handler` + `config`).

---



## Troubleshooting



### IP not being blocked


| Symptom                            | Cause                              | Fix                                             |
| ---------------------------------- | ---------------------------------- | ----------------------------------------------- |
| Log: `sender ... is not trusted`   | Email is from wrong address        | Check `TRUSTED_SENDER` in `.env`                |
| Log: `no alert keyword in content` | Alert text doesn't contain keyword | Check `ALERT_KEYWORDS` or leave blank           |
| Log: `IP ... is whitelisted`       | IP is in `allowed_ips.txt`         | Remove it from the file if blocking is intended |
| Log: `IP ... already blocked`      | IP is already in the rule          | No action needed — rule is already correct      |
| Log: `Rule ... not found`          | `FIREWALL_RULE_NAME` mismatch      | Copy the rule name exactly from SFOS GUI        |
| Log: `Authentication failed`       | Wrong firewall credentials         | Fix `FIREWALL_USERNAME`/`FIREWALL_PASSWORD`     |
| Log: `Upload failed` / `code=5xx`  | SFOS API rejected the update       | Check the full SFOS response in the log         |




### Checking the log

```powershell
Get-Content logs\app.log -Tail 50
```



### Verifying the rule in SFOS GUI

1. **Rules and policies → Firewall rules** — open the `Block IP` rule.
2. Under **Source → Source networks**, the new IP should appear.
3. **Logs → Firewall log** — filter by the blocked IP to confirm traffic is being rejected.



### Testing connectivity to SFOS

```python
from dotenv import load_dotenv; load_dotenv()
from core.config import load_config
from core.firewall_client import SophosClient

cfg = load_config()
c = SophosClient(cfg.firewall_host, cfg.firewall_port, cfg.firewall_username, cfg.firewall_password)
c.authenticate()
import xml.etree.ElementTree as ET
root = c.get_firewall_rule(cfg.firewall_rule_name)
print(ET.tostring(root, encoding="unicode"))
c.logout()
```

