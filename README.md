# ip-karma

IP reputation middleware that receives Wazuh SIEM alerts via webhook and maintains a block-list consolidated by sub-network (IPv4 /32 or IPv6 /64), while keeping individual IP accounting for Threat Intelligence analysis.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.13+ |
| API | FastAPI |
| Database | SQLite (stdlib `sqlite3`) |
| Container | Docker |

---

## Quick Start with Docker

### 1. Build the image

```bash
docker build -t ip-karma:latest .
```

### 2. Run the container

```bash
docker run -d \
  --name ip-karma \
  -p 8000:8000 \
  -v ip-karma-data:/app/data \
  ip-karma:latest
```

The SQLite database (`ip_karma.db`) is stored inside `/app/data` in the container. Mounting a volume at that path (as shown above) keeps the data persistent across container restarts and image updates.

### 3. Verify the service is up

```bash
curl http://localhost:8000/docs
```

---

## API

### `POST /wazuh-alert`

Receives a standard Wazuh alert payload (JSON). The endpoint extracts `data.srcip`, `rule.id`, and `agent.name`.

**Example request:**

```bash
curl -X POST http://localhost:8000/wazuh-alert \
  -H "Content-Type: application/json" \
  -d '{
    "data":  { "srcip": "203.0.113.42" },
    "rule":  { "id": "100001" },
    "agent": { "name": "honeypot-01" }
  }'
```

**Example response:**

```json
{ "status": "ok", "indicator": "203.0.113.42" }
```

For an IPv6 source address, the returned indicator will be the collapsed `/64` prefix:

```bash
curl -X POST http://localhost:8000/wazuh-alert \
  -H "Content-Type: application/json" \
  -d '{
    "data":  { "srcip": "2001:db8::1" },
    "rule":  { "id": "100001" },
    "agent": { "name": "honeypot-01" }
  }'
# → { "status": "ok", "indicator": "2001:db8::/64" }
```

---

## Reputation Logic

| Scenario | Condition | Action |
|----------|-----------|--------|
| **First hit** | Indicator not yet in database | Insert with `level=1`, `strikes=1`, `banned_until = now + 1 h` |
| **Hit within ban window** | Current time ≤ `banned_until` | Increment `strikes`. If `strikes > 50`: increment `level`, reset `strikes=0`, recalculate `banned_until` |
| **Hit after ban expired** | Current time > `banned_until` | Increment `level`, reset `strikes=0`, recalculate `banned_until` |

**TTL formula:** `banned_until = now + min(1 hour × 2^(level − 1), 1 week)`

| Level | Ban duration |
|-------|-------------|
| 1 | 1 h |
| 2 | 2 h |
| 3 | 4 h |
| 4 | 8 h |
| 5 | 16 h |
| 6 | 32 h |
| 7 | 64 h |
| 8 | 128 h |
| ≥ 9 | 168 h (1 week, max) |

---

## Wazuh Manager Integration

### 1. Copy the integration script

Place the following helper script on your Wazuh Manager host at
`/var/ossec/integrations/ip-karma`:

```bash
#!/usr/bin/env python3
"""Wazuh → ip-karma forwarding script."""
import json, sys, urllib.request

ALERT_FILE = sys.argv[1]
IP_KARMA_URL = "http://<IP_KARMA_HOST>:8000/wazuh-alert"  # ← change this

with open(ALERT_FILE) as f:
    payload = json.load(f)

data = json.dumps(payload).encode()
req = urllib.request.Request(
    IP_KARMA_URL,
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST",
)
urllib.request.urlopen(req, timeout=5)
```

Make the script executable:

```bash
chmod 750 /var/ossec/integrations/ip-karma
chown root:wazuh /var/ossec/integrations/ip-karma
```

### 2. Edit `ossec.conf`

Add the `<integration>` block inside the `<ossec_config>` section of
`/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>

  <!-- ─────────────────────────────────────────────
       ip-karma integration
       Forwards alerts with level > 5 to the
       ip-karma reputation middleware.
  ──────────────────────────────────────────────── -->
  <integration>
    <name>ip-karma</name>
    <hook_url>http://<IP_KARMA_HOST>:8000/wazuh-alert</hook_url>
    <level>6</level>
    <alert_format>json</alert_format>
  </integration>

</ossec_config>
```

> **Note:** Replace `<IP_KARMA_HOST>` with the actual hostname or IP address
> where ip-karma is running (e.g. `192.168.1.100` or `ip-karma.internal`).

### 3. Restart the Wazuh Manager

```bash
systemctl restart wazuh-manager
# or, for older installations:
/var/ossec/bin/wazuh-control restart
```

### 4. Verify the integration

After the restart, trigger a test alert above level 5 and confirm a new entry
appears in `ip_karma.db`:

```bash
sqlite3 /app/data/ip_karma.db "SELECT * FROM accounting_log ORDER BY id DESC LIMIT 5;"
sqlite3 /app/data/ip_karma.db "SELECT * FROM reputation_state ORDER BY updated_at DESC LIMIT 5;"
```

---

## Exporting the Denylist to ipset

The `export_ipset.py` script reads all currently-banned indicators from the
database and prints an `ipset restore`-compatible file.

### Basic export (IPv4)

```bash
docker run --rm \
  -v ip-karma-data:/app/data \
  ip-karma:latest \
  python export_ipset.py > denylist.ipset
```

Apply to the running kernel immediately:

```bash
ipset restore < denylist.ipset
```

### Example output

```
create denylist_temp hash:net family inet -exist
flush denylist_temp
add denylist_temp 192.0.2.1
add denylist_temp 203.0.113.0/24
swap denylist_temp denylist
destroy denylist_temp
```

The script creates a temporary set, populates it atomically, swaps it with the
live `denylist` set, and then removes the temporary set — so the active set is
never in an incomplete state.

### IPv6 export

```bash
docker run --rm \
  -v ip-karma-data:/app/data \
  ip-karma:latest \
  python export_ipset.py --family inet6 --set-name denylist6 > denylist6.ipset

ipset restore < denylist6.ipset
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--db` | `/app/data/ip_karma.db` | Path to the SQLite database |
| `--set-name` | `denylist` | Target ipset name |
| `--family` | `inet` | IP family: `inet` (IPv4) or `inet6` (IPv6) |
| `--min-level` | `1` | Minimum reputation level required for inclusion |

Only indicators whose `banned_until` is in the future are included. Use
`--min-level` to restrict the export to higher-confidence entries (e.g.
`--min-level 3` to skip first- and second-level bans).
