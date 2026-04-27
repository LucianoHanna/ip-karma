#!/usr/bin/env python3
"""Export currently-banned indicators from ip-karma as an ipset restore file.

Usage (inside the container):
    python export_ipset.py [options]

Typical docker invocation:
    docker run --rm -v ip-karma-data:/app ip-karma:latest \
        python export_ipset.py > denylist.ipset
    ipset restore < denylist.ipset
"""

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path("/app/ip_karma.db")
DEFAULT_SET = "denylist"


def build_ipset_restore(
    db_path: Path,
    set_name: str,
    family: str,
    min_level: int,
) -> list[str]:
    """Return lines of an ipset restore script for all active ban entries."""
    now = datetime.now(tz=timezone.utc).isoformat()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT indicator FROM reputation_state
            WHERE banned_until > ? AND level >= ?
            ORDER BY indicator
            """,
            (now, min_level),
        ).fetchall()

    # Filter indicators by address family:
    # - inet  → IPv4 host addresses (no colon)
    # - inet6 → IPv6 /64 prefixes  (contains colon)
    indicators = []
    for row in rows:
        indicator = row["indicator"]
        if family == "inet" and ":" not in indicator:
            indicators.append(indicator)
        elif family == "inet6" and ":" in indicator:
            indicators.append(indicator)

    temp_set = f"{set_name}_temp"
    lines = [
        f"create {temp_set} hash:net family {family} -exist",
        f"flush {temp_set}",
    ]
    for indicator in indicators:
        lines.append(f"add {temp_set} {indicator}")
    lines += [
        f"swap {temp_set} {set_name}",
        f"destroy {temp_set}",
    ]
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export ip-karma denylist as an ipset restore file."
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
        help=f"Path to the SQLite database (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--set-name",
        default=DEFAULT_SET,
        help=f"Target ipset name (default: {DEFAULT_SET})",
    )
    parser.add_argument(
        "--family",
        default="inet",
        choices=["inet", "inet6"],
        help="IP address family to export (default: inet)",
    )
    parser.add_argument(
        "--min-level",
        type=int,
        default=1,
        help="Minimum reputation level required for inclusion (default: 1)",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Error: database not found at {db_path}", file=sys.stderr)
        sys.exit(1)

    lines = build_ipset_restore(db_path, args.set_name, args.family, args.min_level)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
