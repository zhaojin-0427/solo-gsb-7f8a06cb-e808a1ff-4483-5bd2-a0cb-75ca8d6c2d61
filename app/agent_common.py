"""控制面代理（网关 / 客户端）共用工具：持久化键、配置下发、混沌开关。"""
from __future__ import annotations

import threading
import time
from typing import Any

from .http_client import HttpError, request_json
from .store import Store


def make_store(data_dir: str, name: str) -> Store:
    return Store(f"{data_dir}/{name}.db")


def retry_forever(fn, *, interval: float = 1.0, label: str = "") -> None:
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - 启动期控制服务可能尚未就绪
            print(f"[bootstrap] {label} 等待控制服务：{exc}", flush=True)
            time.sleep(interval)


def http_call(method: str, url: str, payload: Any = None, *, timeout: float = 10.0):
    return request_json(method, url, payload, timeout=timeout)


def http_error_detail(exc: HttpError) -> dict[str, Any]:
    body = exc.body if isinstance(exc.body, dict) else {"detail": str(exc.body)}
    body.setdefault("detail", exc.body if isinstance(exc.body, str) else str(exc))
    return body


class StepLedger:
    """代理侧的步骤台账：键为 (round_id, step)，终态结果永久保存、重放不重执行。"""

    def __init__(self, store: Store):
        self._store = store
        self._lock = threading.RLock()

    def _key(self, round_id: int, step: str) -> str:
        return f"step:{round_id}:{step}"

    def get(self, round_id: int, step: str) -> dict[str, Any] | None:
        return self._store.get(self._key(round_id, step))

    def put(
        self,
        round_id: int,
        step: str,
        status: str,
        result: dict[str, Any],
        *,
        pending: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            record = {
                "status": status,
                "result": result,
                "pending": pending,
                "updated_at": time.time(),
            }
            self._store.set(self._key(round_id, step), record)
            return record
