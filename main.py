import ipaddress
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Request

from database import init_db, get_connection

STRIKES_THRESHOLD = 50
BASE_TTL_HOURS = 1
MAX_TTL_HOURS = 168  # 1 week cap


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(
    title="ip-karma",
    description="IP reputation middleware for Wazuh alerts",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_ip(srcip: str) -> str:
    """Return the block indicator for a given source IP.

    - IPv4: returns the host address as a string (semantically a /32).
    - IPv6: returns the /64 network prefix (e.g. '2001:db8::/64').
    """
    addr = ipaddress.ip_address(srcip)
    if isinstance(addr, ipaddress.IPv4Address):
        return str(addr)
    # IPv6: collapse to /64 network prefix
    network = ipaddress.IPv6Network(f"{addr}/64", strict=False)
    return str(network)


def _ttl(level: int) -> timedelta:
    hours = min(BASE_TTL_HOURS * (2 ** (level - 1)), MAX_TTL_HOURS)
    return timedelta(hours=hours)


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Core reputation logic
# ---------------------------------------------------------------------------

def _level_up(conn: sqlite3.Connection, indicator: str, level: int, now: datetime) -> None:
    """Escalate the penalty level and recalculate the ban window."""
    new_level = level + 1
    banned_until = now + _ttl(new_level)
    conn.execute(
        """
        UPDATE reputation_state
        SET strikes = 0, level = ?, banned_until = ?, updated_at = ?
        WHERE indicator = ?
        """,
        (new_level, banned_until.isoformat(), now.isoformat(), indicator),
    )


def _increment_strike(
    conn: sqlite3.Connection,
    indicator: str,
    strikes: int,
    level: int,
    banned_until: datetime,
    now: datetime,
) -> None:
    """Increment the strike counter; escalate level if threshold is exceeded."""
    strikes += 1
    if strikes > STRIKES_THRESHOLD:
        _level_up(conn, indicator, level, now)
        return
    conn.execute(
        """
        UPDATE reputation_state
        SET strikes = ?, updated_at = ?
        WHERE indicator = ?
        """,
        (strikes, now.isoformat(), indicator),
    )


def register_indicator_hit(conn: sqlite3.Connection, indicator: str) -> None:
    """Record that *indicator* was seen right now and update its reputation state."""
    now = _now()
    row = conn.execute(
        "SELECT strikes, level, banned_until FROM reputation_state WHERE indicator = ?",
        (indicator,),
    ).fetchone()

    if row is None:
        # Scenario 1: first hit
        banned_until = now + _ttl(1)
        conn.execute(
            """
            INSERT INTO reputation_state (indicator, strikes, level, banned_until, updated_at)
            VALUES (?, 1, 1, ?, ?)
            """,
            (indicator, banned_until.isoformat(), now.isoformat()),
        )
        return

    strikes: int = row["strikes"]
    level: int = row["level"]
    banned_until: datetime = _parse_dt(row["banned_until"])

    if now <= banned_until:
        # Scenario 2: hit within ban window
        _increment_strike(conn, indicator, strikes, level, banned_until, now)
    else:
        # Scenario 3: hit after ban expired
        _level_up(conn, indicator, level, now)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

class AlertPayload:
    """Lightweight extraction helper – avoids heavy Pydantic nesting."""

    def __init__(self, body: dict[str, Any]) -> None:
        try:
            self.srcip: str = body["data"]["srcip"]
            self.rule_id: int = int(body["rule"]["id"])
            self.agent_name: str = body["agent"]["name"]
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Missing or invalid field in payload: {exc}",
            ) from exc


@app.post("/wazuh-alert", status_code=200)
async def wazuh_alert(request: Request) -> dict[str, str]:
    body: dict[str, Any] = await request.json()
    alert = AlertPayload(body)

    # Step A – normalise
    try:
        indicator = normalize_ip(alert.srcip)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid IP address: {exc}") from exc

    now = _now()

    with get_connection() as conn:
        # Step B – accounting log
        conn.execute(
            """
            INSERT INTO accounting_log (indicator_ref, original_ip, source_agent, rule_id, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (indicator, alert.srcip, alert.agent_name, alert.rule_id, now.isoformat()),
        )

        # Step C – reputation state
        register_indicator_hit(conn, indicator)

    return {"status": "ok", "indicator": indicator}
