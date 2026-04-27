from contextlib import contextmanager
from pathlib import Path
from typing import Generator
import sqlite3

DB_PATH = Path("/app/data/ip_karma.db")

DDL = """
CREATE TABLE IF NOT EXISTS reputation_state (
    indicator    TEXT    PRIMARY KEY,
    strikes      INTEGER NOT NULL DEFAULT 0,
    level        INTEGER NOT NULL DEFAULT 1,
    banned_until TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS accounting_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_ref TEXT    NOT NULL,
    original_ip   TEXT    NOT NULL,
    source_agent  TEXT    NOT NULL,
    rule_id       INTEGER NOT NULL,
    timestamp     TEXT    NOT NULL,
    FOREIGN KEY (indicator_ref) REFERENCES reputation_state (indicator)
);
"""


def init_db(db_path: Path = DB_PATH) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.executescript(DDL)


@contextmanager
def get_connection(db_path: Path = DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
