"""网关控制面（MTLS_ROLE=gateway）：启动后向控制服务申领初始材料并提供切换接口。

状态完全持久化在独立卷；重启后从库中恢复信任集与混沌开关，不重新申领、不跳步。
"""
from __future__ import annotations

import os
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .agent_common import StepLedger, http_call, make_store, retry_forever
from .config import CONTROL_HOST, CONTROL_PORT, DATA_DIR, TLS_PORT
from .gateway_data import GatewayDataServer
from .pki import cert_fingerprint, load_cert_pem

K_BOOTSTRAP = "bootstrap"
K_STATE = "gateway_state"  # {trust_gens, trusted_fps, server_fp}
K_REJECT_B = "chaos_reject_b"
K_DROP_NEXT = "drop_next"  # 一次回执丢弃开关：[{round,step}]


class ApplyIn(BaseModel):
    round_id: int
    step: str
    expected_phase: str
    trust_gens: list[str]


def main() -> None:
    import uvicorn

    store = make_store(DATA_DIR, "gateway")
    data_server = GatewayDataServer(port=TLS_PORT, runtime_dir=f"{DATA_DIR}/runtime")
    ledger = StepLedger(store)
    app = FastAPI(title="mTLS 演练 · 网关代理")

    def ca_map(bootstrap: dict, gens: list[str]) -> dict[str, bytes]:
        return {g: bootstrap["ca_pems"][g].encode() for g in gens}

    # ---------- 初始化 / 恢复 ----------
    def bootstrap_or_recover() -> None:
        state = store.get(K_STATE)
        bootstrap = store.get(K_BOOTSTRAP)
        data_server.reject_b = bool(store.get(K_REJECT_B, False))
        if state and bootstrap:
            data_server.configure_initial(
                bootstrap["server_cert_pem"].encode(),
                bootstrap["server_key_pem"].encode(),
                ca_map(bootstrap, state["trust_gens"]),
            )
            return

        def claim() -> dict:
            return http_call(
                "GET",
                f"http://{CONTROL_HOST}:{CONTROL_PORT}/internal/bootstrap/gateway",
            )

        materials: dict = {}
        retry_forever(lambda: materials.update(claim()), label="gateway")
        store.set(K_BOOTSTRAP, materials)
        state = {
            "trust_gens": ["A"],
            "trusted_fps": {
                "A": _fp(materials["ca_pems"]["A"]),
                "B": _fp(materials["ca_pems"]["B"]),
            },
            "server_fp": _fp(materials["server_cert_pem"]),
        }
        store.set(K_STATE, state)
        data_server.configure_initial(
            materials["server_cert_pem"].encode(),
            materials["server_key_pem"].encode(),
            ca_map(materials, ["A"]),
        )

    data_server.start()
    if not data_server.wait_started(timeout=5.0):
        raise RuntimeError(f"网关 TLS 数据面启动失败：{data_server.start_error}")
    bootstrap_or_recover()

    # ---------- 模型辅助 ----------
    def snapshot(status_line: str = "") -> dict:
        state = store.get(K_STATE)
        return {
            "role": "gateway",
            "trust_gens": state["trust_gens"],
            "trusted_fps": state["trusted_fps"],
            "server_fp": state["server_fp"],
            "chaos_reject_b": bool(store.get(K_REJECT_B, False)),
            "drop_pending": store.get(K_DROP_NEXT, []),
            "data_plane": data_server.stats(),
            "status_line": status_line,
        }

    # ---------- 接口 ----------
    @app.get("/state")
    def get_state() -> dict:
        return snapshot()

    @app.post("/apply")
    def apply(body: ApplyIn) -> dict:
        state = store.get(K_STATE)
        prior = ledger.get(body.round_id, body.step)
        if prior:
            return {
                "replayed": True,
                "status": prior["status"],
                "result": prior["result"],
                "state": snapshot("重复同一步：返回原结果，不重复切换"),
            }
        if body.step == "gateway_ab":
            if body.expected_phase != "GATEWAY_AB":
                raise HTTPException(409, f"过期阶段：expected_phase={body.expected_phase}")
            if sorted(body.trust_gens) != ["A", "B"]:
                raise HTTPException(400, "gateway_ab 要求信任集为 A+B")
        elif body.step == "retire_a":
            if body.expected_phase != "RETIRE_A":
                raise HTTPException(409, f"过期阶段：{body.expected_phase}")
            if body.trust_gens != ["B"]:
                raise HTTPException(400, "retire_a 要求信任集仅 B")
        else:
            raise HTTPException(400, f"未知网关步骤：{body.step}")

        # 先持久化待生效记录（崩溃恢复点），再做真实切换
        ledger.put(
            body.round_id,
            body.step,
            "pending",
            {"note": "配置待生效"},
            pending={"trust_gens": body.trust_gens},
        )
        bootstrap = store.get(K_BOOTSTRAP)
        swap = data_server.switch_trust(
            bootstrap["server_cert_pem"].encode(),
            bootstrap["server_key_pem"].encode(),
            ca_map(bootstrap, body.trust_gens),
        )

        new_state = {
            "trust_gens": body.trust_gens,
            "trusted_fps": state["trusted_fps"],
            "server_fp": state["server_fp"],
        }
        store.set(K_STATE, new_state)
        result = {
            "ok": True,
            "applied_at": time.time(),
            "trust_gens": body.trust_gens,
            "config_applied": True,
            "drain": swap,
        }
        ledger.put(body.round_id, body.step, "applied", result)

        # 演练开关：生效后丢弃一次回执（控制服务表现为 503，可安全重试拿到原结果）
        drops = store.get(K_DROP_NEXT, [])
        dropped = False
        for i, item in enumerate(drops):
            if item.get("round") == body.round_id and item.get("step") == body.step:
                drops.pop(i)
                store.set(K_DROP_NEXT, drops)
                dropped = True
                break
        if dropped:
            raise HTTPException(503, {"detail": "回执已被演练开关丢弃（代理实际已生效，可安全重试）",
                                      "actually_applied": True, "trust_gens": body.trust_gens})
        return {"replayed": False, "status": "applied", "result": result, "state": snapshot()}

    @app.post("/chaos/reject-b")
    def set_reject_b(body: dict) -> dict:
        enabled = bool(body.get("enabled", False))
        store.set(K_REJECT_B, enabled)
        data_server.set_reject_b(enabled)
        return {"ok": True, "chaos_reject_b": enabled}

    @app.post("/chaos/drop-receipt")
    def arm_drop(body: dict) -> dict:
        drops = store.get(K_DROP_NEXT, [])
        item = {"round": body.get("round_id"), "step": body.get("step")}
        if item not in drops:
            drops.append(item)
        store.set(K_DROP_NEXT, drops)
        return {"ok": True, "drop_pending": drops}

    @app.post("/internal/reset")
    def internal_reset() -> dict:
        """演练复位：信任集回到仅 A，清除步骤台账与混沌开关（仅控制服务编排调用）。"""
        store.set(K_REJECT_B, False)
        data_server.set_reject_b(False)
        bootstrap = store.get(K_BOOTSTRAP)
        if bootstrap:
            data_server.switch_trust(
                bootstrap["server_cert_pem"].encode(),
                bootstrap["server_key_pem"].encode(),
                ca_map(bootstrap, ["A"]),
            )
        state = store.get(K_STATE)
        if state:
            state["trust_gens"] = ["A"]
            store.set(K_STATE, state)
        store.delete_prefix("step:")
        store.set(K_DROP_NEXT, [])
        return {"ok": True, "state": snapshot("复位完成：仅信任根 A")}

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("AGENT_PORT", "8081")))


def _fp(pem_text: str) -> str:
    return cert_fingerprint(load_cert_pem(pem_text.encode()))
