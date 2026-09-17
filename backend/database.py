"""
SQLite database — SignalTrust v3
Phone numbers are stored as SHA-256 hashes only.
A masked display string (e.g. "+91-XXXXX-00001") is kept separately.
"""

import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "signaltrust.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def hash_phone(phone: str) -> str:
    """One-way SHA-256 hash.  The plaintext never touches the DB."""
    return hashlib.sha256(phone.strip().encode()).hexdigest()


def mask_phone(phone: str) -> str:
    """Keep last 5 digits, mask the rest — e.g. +91-XXXXX-00001"""
    digits = "".join(c for c in phone if c.isdigit())
    if len(digits) >= 5:
        return "XXXXX-" + digits[-5:]
    return "XXXXX"


def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            cluster     TEXT DEFAULT 'unknown'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            user_a  TEXT NOT NULL,
            user_b  TEXT NOT NULL,
            PRIMARY KEY (user_a, user_b),
            FOREIGN KEY (user_a) REFERENCES users(id),
            FOREIGN KEY (user_b) REFERENCES users(id)
        )
    """)

    # phone      = SHA-256 hash of the real number
    # phone_mask = display-safe masked string
    # note       = optional free-text human detail
    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id TEXT NOT NULL,
            phone       TEXT NOT NULL,
            phone_mask  TEXT NOT NULL DEFAULT '',
            category    TEXT NOT NULL,
            note        TEXT DEFAULT '',
            timestamp   REAL NOT NULL,
            confirmed   INTEGER DEFAULT 0,
            FOREIGN KEY (reporter_id) REFERENCES users(id)
        )
    """)

    # confirm_log prevents one user from repeatedly confirming their own reports
    c.execute("""
        CREATE TABLE IF NOT EXISTS confirm_log (
            report_id   INTEGER NOT NULL,
            user_id     TEXT NOT NULL,
            confirmed_at REAL NOT NULL,
            PRIMARY KEY (report_id, user_id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS call_gates (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            gate_id      TEXT NOT NULL UNIQUE,
            caller_phone TEXT NOT NULL,
            caller_name  TEXT,
            callee_id    TEXT NOT NULL,
            risk_level   TEXT NOT NULL,
            score        REAL NOT NULL,
            explanation  TEXT,
            status       TEXT DEFAULT 'pending',
            created_at   REAL NOT NULL,
            decided_at   REAL,
            FOREIGN KEY (callee_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
