import json
import sqlite3
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from flowguard.baseline import Baseline


class Store:
    def __init__(self, path, max_records=100_000):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=10)
        self.connection.row_factory = sqlite3.Row
        self.max_records = max_records
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript("""
        CREATE TABLE IF NOT EXISTS baselines (
          id INTEGER PRIMARY KEY, created TEXT NOT NULL, name TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
          id INTEGER PRIMARY KEY, created TEXT NOT NULL, mode TEXT NOT NULL, input TEXT NOT NULL,
          learning INTEGER NOT NULL, status TEXT NOT NULL, baseline_id INTEGER, config TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS metrics (
          id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL, timestamp REAL NOT NULL,
          duration REAL NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
          packet_rate REAL NOT NULL, byte_rate REAL NOT NULL, protocols TEXT NOT NULL,
          ports TEXT NOT NULL, sources TEXT NOT NULL, partial INTEGER NOT NULL, untracked INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL, timestamp REAL NOT NULL,
          detector TEXT NOT NULL, severity TEXT NOT NULL, observed REAL NOT NULL,
          threshold REAL NOT NULL, reason TEXT NOT NULL, source TEXT, destination TEXT, baseline REAL);
        CREATE INDEX IF NOT EXISTS metrics_session ON metrics(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS alerts_session ON alerts(session_id, timestamp);
        """)

    def close(self):
        self.connection.close()

    def baseline(self, identifier=None):
        query = (
            "SELECT * FROM baselines WHERE id=?"
            if identifier is not None
            else "SELECT * FROM baselines ORDER BY id DESC LIMIT 1"
        )
        row = self.connection.execute(query, (identifier,) if identifier is not None else ()).fetchone()
        if identifier is not None and row is None:
            raise ValueError(f"Baseline {identifier} does not exist")
        return (row["id"], Baseline(**json.loads(row["data"]))) if row else (None, None)

    def save_baseline(self, baseline, name):
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO baselines(created,name,data) VALUES(?,?,?)",
                (self.now(), name, json.dumps(asdict(baseline))),
            )
        return cursor.lastrowid

    @staticmethod
    def now():
        return datetime.now(UTC).isoformat()

    def session(self, mode, input_name, learning, baseline_id, config):
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO sessions(created,mode,input,learning,status,baseline_id,config) VALUES(?,?,?,?,?,?,?)",
                (
                    self.now(),
                    mode,
                    str(input_name),
                    learning,
                    "running",
                    baseline_id,
                    json.dumps(asdict(config)),
                ),
            )
        return cursor.lastrowid

    def end_session(self, identifier, status, baseline_id=None):
        with self.connection:
            self.connection.execute(
                "UPDATE sessions SET status=?, baseline_id=COALESCE(?,baseline_id) WHERE id=?",
                (status, baseline_id, identifier),
            )

    def save_window(self, session_id, window, alerts):
        sources = {key: value.packets for key, value in window.sources.items()}
        with self.connection:
            self.connection.execute(
                """INSERT INTO metrics
                (session_id,timestamp,duration,packets,bytes,packet_rate,byte_rate,protocols,ports,sources,partial,untracked)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    session_id,
                    window.start,
                    window.duration,
                    window.packets,
                    window.bytes,
                    window.packet_rate,
                    window.byte_rate,
                    json.dumps(window.protocols),
                    json.dumps(window.ports),
                    json.dumps(sources),
                    window.partial,
                    window.untracked_source_packets,
                ),
            )
            self.connection.executemany(
                """INSERT INTO alerts
                (session_id,timestamp,detector,severity,observed,threshold,reason,source,destination,baseline)
                VALUES(?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        session_id,
                        a.timestamp,
                        a.detector,
                        a.severity,
                        a.observed,
                        a.threshold,
                        a.reason,
                        a.source,
                        a.destination,
                        a.baseline,
                    )
                    for a in alerts
                ],
            )
            # Indexed cutoffs bound retained rows, independent of process lifetime.
            for table in ("metrics", "alerts"):
                self.connection.execute(
                    f"DELETE FROM {table} WHERE id <= COALESCE((SELECT id FROM {table} ORDER BY id DESC LIMIT 1 OFFSET ?),-1)",
                    (self.max_records,),
                )
