"""SQLite 持久化层：控制服务 / 网关 / 客户端各自独立的卷与库。

控制服务存轮次、阶段、命令回执与权威代际材料；代理只存自己的实际生效状态。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS kv (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rounds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phase TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS steps (
                    round_id INTEGER NOT NULL,
                    step TEXT NOT NULL,
                    status TEXT NOT NULL,
                    expected_phase TEXT NOT NULL,
                    result TEXT,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (round_id, step)
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    at REAL NOT NULL,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                """
            )

    # ---- 通用 KV ----
    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute(
                "SELECT v FROM kv WHERE k=?", (key,)
            ).fetchone()
        return json.loads(row["v"]) if row else default

    def set(self, key: str, value: Any) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO kv(k,v) VALUES(?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (key, json.dumps(value)),
            )

    def delete(self, *keys: str) -> None:
        if not keys:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                "DELETE FROM kv WHERE k=?", [(k,) for k in keys]
            )

    def delete_prefix(self, prefix: str) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM kv WHERE k LIKE ?", (prefix + "%",))
            return cur.rowcount

    def keys(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute("SELECT k FROM kv ORDER BY k").fetchall()
        return [r["k"] for r in rows]

    # ---- 轮次 / 阶段 ----
    def get_round(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM rounds ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def start_round(self, phase: str, now: float) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO rounds(phase, created_at) VALUES(?,?)",
                (phase, now),
            )
            return int(cur.lastrowid)

    def set_phase(self, round_id: int, phase: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE rounds SET phase=? WHERE id=?", (phase, round_id)
            )

    # ---- 步骤回执 ----
    def get_step(self, round_id: int, step: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM steps WHERE round_id=? AND step=?",
                (round_id, step),
            ).fetchone()
        return dict(row) if row else None

    def list_steps(self, round_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM steps WHERE round_id=? ORDER BY updated_at",
                (round_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def upsert_step(
        self,
        round_id: int,
        step: str,
        status: str,
        expected_phase: str,
        result: dict[str, Any] | None,
        now: float,
    ) -> None:
        payload = json.dumps(result) if result is not None else None
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO steps(round_id,step,status,expected_phase,result,updated_at)"
                " VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(round_id,step) DO UPDATE SET "
                "status=excluded.status,result=excluded.result,updated_at=excluded.updated_at",
                (round_id, step, status, expected_phase, payload, now),
            )

    def clear_rounds(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM steps")
            self._conn.execute("DELETE FROM rounds")

    # ---- 事件日志 ----
    def log_event(self, now: float, kind: str, message: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO events(at,kind,message) VALUES(?,?,?)",
                (now, kind, message),
            )
            self._conn.execute(
                "DELETE FROM events WHERE id NOT IN "
                "(SELECT id FROM events ORDER BY id DESC LIMIT 100)"
            )

    def list_events(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
