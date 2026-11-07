"""SQLite persistence: loops, events (replay + SSE), policies, held-out evals. Connects lazily."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS loops(id TEXT PRIMARY KEY, created REAL, status TEXT, config TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS events(loop_id TEXT, seq INTEGER, type TEXT, data TEXT, PRIMARY KEY(loop_id, seq));
CREATE TABLE IF NOT EXISTS policies(loop_id TEXT, version INTEGER, body TEXT, PRIMARY KEY(loop_id, version));
CREATE TABLE IF NOT EXISTS evals(id TEXT PRIMARY KEY, loop_id TEXT, created REAL, status TEXT, request TEXT, result TEXT);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()

    @property
    def c(self) -> sqlite3.Connection:
        if self._conn is None:
            if self.path != ":memory:":
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
        return self._conn

    def _run(self, sql: str, args: tuple = ()) -> None:
        with self._lock:
            self.c.execute(sql, args)
            self.c.commit()

    def _all(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.c.execute(sql, args).fetchall()

    # ---------- loops ----------
    def create_loop(self, loop_id: str, config: dict, state: dict) -> None:
        self._run("INSERT INTO loops VALUES(?,?,?,?,?)",
                  (loop_id, time.time(), state["status"], json.dumps(config), json.dumps(state)))

    def save_state(self, loop_id: str, state: dict) -> None:
        self._run("UPDATE loops SET status=?, state=? WHERE id=?", (state["status"], json.dumps(state), loop_id))

    def get_loop(self, loop_id: str) -> Optional[dict]:
        rows = self._all("SELECT * FROM loops WHERE id=?", (loop_id,))
        if not rows:
            return None
        r = rows[0]
        return {"id": r["id"], "created": r["created"], "status": r["status"],
                "config": json.loads(r["config"]), "state": json.loads(r["state"])}

    def list_loops(self, limit: int = 20) -> list[dict]:
        return [{"id": r["id"], "created": r["created"], "status": r["status"]}
                for r in self._all("SELECT id, created, status FROM loops ORDER BY created DESC LIMIT ?", (limit,))]

    # ---------- events ----------
    def add_event(self, loop_id: str, seq: int, type_: str, data: dict) -> None:
        self._run("INSERT OR REPLACE INTO events VALUES(?,?,?,?)", (loop_id, seq, type_, json.dumps(data)))

    def events(self, loop_id: str, after_seq: int = -1) -> list[dict]:
        rows = self._all("SELECT seq, type, data FROM events WHERE loop_id=? AND seq>? ORDER BY seq", (loop_id, after_seq))
        return [{"loop_id": loop_id, "seq": r["seq"], "type": r["type"], "data": json.loads(r["data"])} for r in rows]

    # ---------- policies ----------
    def save_policy(self, loop_id: str, version: int, body: dict) -> None:
        self._run("INSERT OR REPLACE INTO policies VALUES(?,?,?)", (loop_id, version, json.dumps(body)))

    def get_policy(self, version: int, loop_id: Optional[str] = None) -> Optional[tuple[str, dict]]:
        if loop_id:
            rows = self._all("SELECT loop_id, body FROM policies WHERE loop_id=? AND version=?", (loop_id, version))
        else:
            rows = self._all("SELECT p.loop_id, p.body FROM policies p JOIN loops l ON l.id=p.loop_id "
                             "WHERE p.version=? ORDER BY l.created DESC LIMIT 1", (version,))
        return (rows[0]["loop_id"], json.loads(rows[0]["body"])) if rows else None

    # ---------- evals ----------
    def create_eval(self, eval_id: str, loop_id: str, request: dict) -> None:
        self._run("INSERT INTO evals VALUES(?,?,?,?,?,NULL)", (eval_id, loop_id, time.time(), "running", json.dumps(request)))

    def finish_eval(self, eval_id: str, status: str, result: Any) -> None:
        self._run("UPDATE evals SET status=?, result=? WHERE id=?", (status, json.dumps(result), eval_id))

    def get_eval(self, eval_id: str) -> Optional[dict]:
        rows = self._all("SELECT * FROM evals WHERE id=?", (eval_id,))
        if not rows:
            return None
        r = rows[0]
        return {"id": r["id"], "loop_id": r["loop_id"], "status": r["status"], "request": json.loads(r["request"]),
                "result": json.loads(r["result"]) if r["result"] else None}
