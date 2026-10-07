"""客户端代理（MTLS_ROLE=client）：持久保存生效证书/私钥与代际，切换必须先试真实握手。

规则：
- 首次启动向控制服务申领 A 叶子证书（由根 A 签发）与网关服务端 CA。
- 收到 B 候选材料后只保存为 candidate，不影响生效证书。
- switch-b：先用候选 B 发起真实 TLS 握手；失败保持 A，成功才切换生效证书。
- 每步结果按 (round_id, step) 台账保存；重复同一步返回原结果、不重新签发、不重复尝试。
"""
from __future__ import annotations

import os
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .agent_common import StepLedger, http_call, make_store, retry_forever
from .config import CLIENT_NAME, CONTROL_HOST, CONTROL_PORT, DATA_DIR, GATEWAY_HOST
from .pki import cert_fingerprint, load_cert_pem
from .tls_probe import tls_probe

K_BOOTSTRAP = "bootstrap"          # {server_ca_pem, effective:{cert_pem,key_pem,gen}}
K_CANDIDATE = "candidate_b"        # {cert_pem,key_pem} | None
K_DROP_NEXT = "drop_next"


class CandidateIn(BaseModel):
    round_id: int
    expected_phase: str
    cert_pem: str
    key_pem: str


class SwitchIn(BaseModel):
    round_id: int
    step: str
    expected_phase: str


class ProbeIn(BaseModel):
    gen: str = "effective"          # effective | A | B
    delay: float = 0.0


def main() -> None:
    import uvicorn

    store = make_store(DATA_DIR, f"client-{CLIENT_NAME}")
    ledger = StepLedger(store)
    app = FastAPI(title=f"mTLS 演练 · 客户端 {CLIENT_NAME}")

    def bootstrap_or_recover() -> None:
        if store.get(K_BOOTSTRAP):
            return

        def claim() -> dict:
            return http_call(
                "GET",
                f"http://{CONTROL_HOST}:{CONTROL_PORT}/internal/bootstrap/client/{CLIENT_NAME}",
            )

        materials: dict = {}
        retry_forever(lambda: materials.update(claim()), label=f"client:{CLIENT_NAME}")
        # 控制服务只在轮换开始后才签发 B；初始申领只返回 A 生效材料
        initial_a = {
            "gen": "A",
            "cert_pem": materials["cert_pem"],
            "key_pem": materials["key_pem"],
        }
        store.set(
            K_BOOTSTRAP,
            {"server_ca_pem": materials["server_ca_pem"],
             "effective": dict(initial_a), "initial_a": initial_a},
        )
        store.set(K_CANDIDATE, None)

    bootstrap_or_recover()

    def effective() -> dict:
        return store.get(K_BOOTSTRAP)["effective"]

    def snapshot(status_line: str = "") -> dict:
        boot = store.get(K_BOOTSTRAP)
        eff = boot["effective"]
        cand = store.get(K_CANDIDATE)
        return {
            "role": "client",
            "name": CLIENT_NAME,
            "effective_gen": eff["gen"],
            "effective_fp": _fp(eff["cert_pem"]),
            "candidate_gen": "B" if cand else None,
            "candidate_fp": _fp(cand["cert_pem"]) if cand else None,
            "gateway_host": GATEWAY_HOST,
            "drop_pending": store.get(K_DROP_NEXT, []),
            "status_line": status_line,
        }

    @app.get("/state")
    def get_state() -> dict:
        return snapshot()

    @app.post("/candidate-b")
    def deliver_candidate(body: CandidateIn) -> dict:
        if body.expected_phase != "GATEWAY_AB":
            raise HTTPException(409, f"过期阶段：{body.expected_phase}，候选 B 仅在 A/B 共信阶段下发")
        # 幂等：重复下发相同指纹只返回现状
        existing = store.get(K_CANDIDATE)
        fp = _fp(body.cert_pem)
        if existing and _fp(existing["cert_pem"]) == fp:
            return {"ok": True, "replayed": True, "candidate_fp": fp, "state": snapshot()}
        store.set(
            K_CANDIDATE, {"cert_pem": body.cert_pem, "key_pem": body.key_pem}
        )
        return {"ok": True, "replayed": False, "candidate_fp": fp, "state": snapshot()}

    @app.post("/apply")
    def apply(body: SwitchIn) -> dict:
        if body.step != "switch-b":
            raise HTTPException(400, f"客户端不支持步骤：{body.step}")
        if body.expected_phase != "CLIENT_SWITCH":
            raise HTTPException(409, f"过期阶段：{body.expected_phase}，当前要求 CLIENT_SWITCH")
        prior = ledger.get(body.round_id, body.step)
        if prior:
            return {
                "replayed": True,
                "status": prior["status"],
                "result": prior["result"],
                "state": snapshot("重复同一步：返回原结果，不重新尝试握手"),
            }

        candidate = store.get(K_CANDIDATE)
        if not candidate:
            failed = {
                "ok": False,
                "switched": False,
                "reason": "候选 B 证书缺失（未完成下发）",
                "config_applied": False,
                "at": time.time(),
            }
            ledger.put(body.round_id, body.step, "failed", failed)
            return {"replayed": False, "status": "failed", "result": failed,
                    "state": snapshot("候选缺失，停在 A")}

        boot = store.get(K_BOOTSTRAP)
        # 关键：先用候选 B 试真实握手，生效证书仍为 A
        trial = tls_probe(
            candidate["cert_pem"].encode(),
            candidate["key_pem"].encode(),
            boot["server_ca_pem"].encode(),
            label=f"{CLIENT_NAME}-candidate-B-trial",
        )
        if not trial["ok"]:
            failed = {
                "ok": False,
                "switched": False,
                "stayed_gen": "A",
                "reason": trial["reason"] or "B 候选握手失败",
                "config_applied": False,
                "trial": _trial_view(trial),
                "at": time.time(),
            }
            # 失败是稳定终态：保留原结果，避免反复尝试或误切换；复位演练后再开新一轮
            ledger.put(body.round_id, body.step, "failed", failed)
            return {"replayed": False, "status": "failed", "result": failed,
                    "state": snapshot("B 试握手失败，保持 A")}

        # 握手成功才切换生效证书
        new_eff = {
            "gen": "B",
            "cert_pem": candidate["cert_pem"],
            "key_pem": candidate["key_pem"],
        }
        boot["effective"] = new_eff
        store.set(K_BOOTSTRAP, boot)
        result = {
            "ok": True,
            "switched": True,
            "gen": "B",
            "fingerprint": _fp(candidate["cert_pem"]),
            "config_applied": True,
            "handshake_ok": True,
            "trial": _trial_view(trial),
            "at": time.time(),
        }
        ledger.put(body.round_id, body.step, "applied", result)

        drops = store.get(K_DROP_NEXT, [])
        dropped = False
        for i, item in enumerate(drops):
            if item.get("round") == body.round_id and item.get("step") == body.step:
                drops.pop(i)
                store.set(K_DROP_NEXT, drops)
                dropped = True
                break
        if dropped:
            raise HTTPException(503, {"detail": "回执已被演练开关丢弃（客户端实际已切到 B，可安全重试）",
                                      "actually_applied": True, "effective_gen": "B"})
        return {"replayed": False, "status": "applied", "result": result,
                "state": snapshot("B 试握手成功，已切换生效证书")}

    @app.post("/probe")
    def probe(body: ProbeIn) -> dict:
        """页面上的手动探测：用本进程保存的指定代际证书发起真实握手。"""
        boot = store.get(K_BOOTSTRAP)
        cand = store.get(K_CANDIDATE)
        if body.gen in ("effective", "A", "B"):
            target_gen = effective()["gen"] if body.gen == "effective" else body.gen
        else:
            raise HTTPException(400, "gen 仅支持 effective / A / B")

        if target_gen == boot["effective"]["gen"]:
            mat = boot["effective"]
        elif target_gen == "B" and cand:
            mat = cand
        else:
            return {
                "ok": False,
                "handshake_ok": False,
                "gen": target_gen,
                "reason": f"本进程没有 {target_gen} 代材料（生效：{boot['effective']['gen']}）",
            }
        result = tls_probe(
            mat["cert_pem"].encode(),
            mat["key_pem"].encode(),
            boot["server_ca_pem"].encode(),
            delay=body.delay,
            label=f"{CLIENT_NAME}-manual-{target_gen}",
        )
        result["gen"] = target_gen
        return result

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
        """演练复位：生效证书恢复初始 A（不重新签发），清除候选 B、台账与混沌。"""
        boot = store.get(K_BOOTSTRAP)
        initial_a = boot.get("initial_a") or boot["effective"]
        boot["effective"] = dict(initial_a)
        store.set(K_BOOTSTRAP, boot)
        store.set(K_CANDIDATE, None)
        store.delete_prefix("step:")
        store.set(K_DROP_NEXT, [])
        return {"ok": True, "state": snapshot("复位完成：生效证书恢复初始 A")}

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "gen": effective()["gen"]}

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("AGENT_PORT", "8081")))


def _fp(pem_text: str) -> str:
    return cert_fingerprint(load_cert_pem(pem_text.encode()))


def _trial_view(trial: dict) -> dict:
    return {
        "ok": trial["ok"],
        "handshake_ok": trial["handshake_ok"],
        "http_status": trial["http_status"],
        "elapsed_ms": trial["elapsed_ms"],
        "reason": trial["reason"],
        "gateway": trial.get("gateway"),
    }
