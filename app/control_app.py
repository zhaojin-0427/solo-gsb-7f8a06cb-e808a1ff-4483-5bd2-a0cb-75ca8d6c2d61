"""控制服务（MTLS_ROLE=control）：PKI 权威、轮换编排、状态聚合与演练页面。

阶段机：
  INIT ──start──▶ GATEWAY_AB ──confirm_b──▶ CLIENT_SWITCH ──(两客户端均 B)──▶ RETIRE_A
                 ▲ 任一客户端切换失败则停在此（A/B 共信，A、B 客户端仍可连接）
  RETIRE_A 执行并确认旧 A 新握手失败、B 继续成功后 ▶ DONE

每步必须携带 expected_phase；同一步重放只返回原结果；过期阶段返回 409；
已有进行中的轮次时再次发起轮换返回 409。
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel

from .agent_common import http_call, make_store
from .config import (
    CLIENT_NAMES,
    CONTROL_PORT,
    DATA_DIR,
    GATEWAY_AGENT_URL,
    GATEWAY_HOST,
    GATEWAY_TLS_PORT,
    client_agent_url,
)
from .http_client import HttpError
from .pki import (
    CertKey,
    cert_fingerprint,
    create_ca,
    fp_short,
    issue_leaf,
    load_cert_pem,
)
from .tls_probe import tls_probe

K_PKI = "pki_materials"          # 初始与 B 材料（PEM）
K_ROUND_OPEN = "round_open"      # 是否存在进行中轮次
PHASE_INIT = "INIT"
PHASE_GW_AB = "GATEWAY_AB"
PHASE_CLIENT = "CLIENT_SWITCH"
PHASE_RETIRE = "RETIRE_A"
PHASE_DONE = "DONE"

TERMINAL_PHASES = {PHASE_DONE}
STEP_ORDER = ["gateway_ab", "confirm_b", "switch-client1", "switch-client2", "retire_a"]


class StartIn(BaseModel):
    expected_phase: str | None = None


class StepIn(BaseModel):
    step: str
    expected_phase: str


class ClientProbeIn(BaseModel):
    client: str
    gen: str = "effective"
    delay: float = 0.0


class ChaosIn(BaseModel):
    target: str          # gateway / client1 / client2
    kind: str            # reject-b / drop-receipt
    enabled: bool = True
    round_id: int | None = None
    step: str | None = None


def main() -> None:
    import uvicorn

    store = make_store(DATA_DIR, "control")
    app = FastAPI(title="mTLS 信任根轮换演练 · 控制服务")
    lock = threading.RLock()

    # ---------------------------------------------------------------- PKI
    def ensure_pki() -> dict[str, Any]:
        materials = store.get(K_PKI)
        if materials:
            return materials
        server_ca = create_ca("Server-CA")
        root_a = create_ca("Root-CA-A")
        root_b = create_ca("Root-CA-B")
        server = issue_leaf(
            server_ca,
            "gateway",
            server=True,
            sans=[GATEWAY_HOST, "localhost", "127.0.0.1", "gateway"],
        )
        leaves_a: dict[str, CertKey] = {
            name: issue_leaf(root_a, name, client=True) for name in CLIENT_NAMES
        }
        canary_a = issue_leaf(root_a, "canary-a", client=True)
        materials = {
            "server_ca": _ck(server_ca),
            "roots": {"A": _ck(root_a), "B": _ck(root_b)},
            "server": _ck(server),
            "leaves_a": {n: _ck(c) for n, c in leaves_a.items()},
            "canary_a": _ck(canary_a),
            "b": None,  # 轮换发起时才签发，且只签一次
        }
        store.set(K_PKI, materials)
        store.log_event(time.time(), "pki", "初始 PKI 生成：Server-CA、根 A/B，客户端初始由根 A 签发")
        return materials

    def ensure_b_materials(materials: dict[str, Any]) -> dict[str, Any]:
        """B 叶子只签发一次；重放/重启/回执丢失都复用同一张证书。"""
        if materials.get("b"):
            return materials["b"]
        root_b = _ck_to_obj(materials["roots"]["B"])
        leaves_b = {
            name: _ck(issue_leaf(root_b, name, client=True)) for name in CLIENT_NAMES
        }
        canary_b = _ck(issue_leaf(root_b, "canary-b", client=True))
        b = {"leaves_b": leaves_b, "canary_b": canary_b}
        materials["b"] = b
        store.set(K_PKI, materials)
        store.log_event(time.time(), "pki", "根 B 客户端证书签发（仅一次，后续步骤复用）")
        return b

    pki = ensure_pki()

    # ------------------------------------------------------------ 轮次工具
    def current_round() -> dict[str, Any] | None:
        return store.get_round()

    def phase_of(rd: dict[str, Any] | None) -> str:
        return rd["phase"] if rd else PHASE_INIT

    def step_record(rd: dict[str, Any], step: str) -> dict[str, Any] | None:
        return store.get_step(rd["id"], step)

    def save_step(
        rd: dict[str, Any],
        step: str,
        status: str,
        expected_phase: str,
        result: dict[str, Any],
    ) -> None:
        store.upsert_step(rd["id"], step, status, expected_phase, result, time.time())

    def require_expected(in_phase: str, rd: dict[str, Any] | None) -> None:
        actual = phase_of(rd)
        if in_phase != actual:
            raise HTTPException(
                409,
                f"过期阶段不得推进：携带 expected_phase={in_phase}，实际阶段={actual}",
            )

    def agent(method: str, url: str, payload: Any = None, *, timeout: float = 10.0):
        try:
            return http_call(method, url, payload, timeout=timeout)
        except HttpError as exc:
            raise HTTPException(
                exc.status,
                {"detail": f"代理返回 {exc.status}", "upstream": exc.body},
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(502, f"代理不可达：{exc}") from exc

    def probe(leaf: CertKey, *, delay: float = 0.0, label: str = "") -> dict[str, Any]:
        return tls_probe(
            leaf.cert_pem(),
            leaf.key_pem(),
            _ck_to_obj(pki["server_ca"]).cert_pem(),
            host=os.environ.get("PROBE_GATEWAY_HOST", GATEWAY_HOST),
            port=int(os.environ.get("PROBE_GATEWAY_PORT", str(GATEWAY_TLS_PORT))),
            delay=delay,
            label=label,
        )

    def expected_phase_for_step(step: str, rd: dict[str, Any]) -> str:
        rec = step_record(rd, step)
        return rec["expected_phase"] if rec else "?"

    # ------------------------------------------------------ 内部申领接口
    @app.get("/internal/bootstrap/gateway")
    def bootstrap_gateway() -> dict:
        return {
            "server_cert_pem": pki["server"]["cert_pem"],
            "server_key_pem": pki["server"]["key_pem"],
            "ca_pems": {
                "A": pki["roots"]["A"]["cert_pem"],
                "B": pki["roots"]["B"]["cert_pem"],
            },
        }

    @app.get("/internal/bootstrap/client/{name}")
    def bootstrap_client(name: str) -> dict:
        if name not in CLIENT_NAMES:
            raise HTTPException(404, "未知客户端")
        leaf = pki["leaves_a"][name]
        return {
            "cert_pem": leaf["cert_pem"],
            "key_pem": leaf["key_pem"],
            "gen": "A",
            "server_ca_pem": pki["server_ca"]["cert_pem"],
        }

    # --------------------------------------------------------- 状态聚合
    def _agent_state(base: str) -> dict[str, Any]:
        try:
            return http_call("GET", f"{base}/state")
        except HttpError as exc:
            return {"unreachable": True, "status": exc.status, "body": exc.body}
        except Exception as exc:  # noqa: BLE001
            return {"unreachable": True, "error": str(exc)}

    def step_view(rd: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not rd:
            return []
        return [
            {
                "step": s["step"],
                "status": s["status"],
                "expected_phase": s["expected_phase"],
                "result": json_loads(s["result"]),
                "updated_at": s["updated_at"],
            }
            for s in store.list_steps(rd["id"])
        ]

    def full_state() -> dict[str, Any]:
        rd = current_round()
        steps = step_view(rd)
        agents = {"gateway": _agent_state(GATEWAY_AGENT_URL)}
        clients: dict[str, Any] = {}
        for name in CLIENT_NAMES:
            clients[name] = _agent_state(client_agent_url(name))
        agents["clients"] = clients
        failure = None
        for s in steps:
            if s["status"] == "failed" and s["result"]:
                failure = {"step": s["step"], "reason": s["result"].get("reason")}
        return {
            "phase": phase_of(rd),
            "round_id": rd["id"] if rd else None,
            "round_open": bool(rd) and rd["phase"] not in TERMINAL_PHASES,
            "steps": steps,
            "step_order": STEP_ORDER,
            "agents": agents,
            "fingerprints": {
                "root_a": fp_short(cert_fingerprint(load_cert_pem(pki["roots"]["A"]["cert_pem"].encode()))),
                "root_b": fp_short(cert_fingerprint(load_cert_pem(pki["roots"]["B"]["cert_pem"].encode()))),
                "server_ca": fp_short(cert_fingerprint(load_cert_pem(pki["server_ca"]["cert_pem"].encode()))),
                "server": fp_short(cert_fingerprint(load_cert_pem(pki["server"]["cert_pem"].encode()))),
                "clients_a": {
                    n: fp_short(cert_fingerprint(load_cert_pem(pki["leaves_a"][n]["cert_pem"].encode())))
                    for n in CLIENT_NAMES
                },
                "clients_b": {
                    n: fp_short(cert_fingerprint(load_cert_pem(pki["b"]["leaves_b"][n]["cert_pem"].encode())))
                    for n in CLIENT_NAMES
                } if pki.get("b") else {},
                "canary_a": fp_short(cert_fingerprint(load_cert_pem(pki["canary_a"]["cert_pem"].encode()))),
                "canary_b": fp_short(cert_fingerprint(load_cert_pem(pki["b"]["canary_b"]["cert_pem"].encode())))
                if pki.get("b") else None,
            },
            "last_failure": failure,
            "events": store.list_events(20),
        }

    @app.get("/api/state")
    def api_state() -> dict:
        return full_state()

    # ----------------------------------------------------------- 发起轮换
    @app.post("/api/rotate/start")
    def rotate_start(body: StartIn) -> dict:
        with lock:
            rd = current_round()
            if rd and rd["phase"] not in TERMINAL_PHASES:
                raise HTTPException(409, f"已有进行中的轮次 #{rd['id']}（阶段 {rd['phase']}），并发轮换冲突")
            if body.expected_phase and body.expected_phase != phase_of(rd):
                raise HTTPException(409, f"expected_phase={body.expected_phase} 与实际 {phase_of(rd)} 不符")
            ensure_b_materials(pki)
            rid = store.start_round(PHASE_GW_AB, time.time())
            store.set(K_ROUND_OPEN, rid)
            store.log_event(time.time(), "round", f"轮次 #{rid} 发起：进入 {PHASE_GW_AB}（网关先同时信任 A/B）")
            new_rd = store.get_round()
            return {"ok": True, "round_id": rid, "phase": new_rd["phase"], "state": full_state()}

    # ------------------------------------------------------------- 推进一步
    @app.post("/api/rotate/step")
    def rotate_step(body: StepIn) -> dict:
        with lock:
            rd = current_round()
            step = body.step
            if step not in STEP_ORDER:
                raise HTTPException(400, f"未知步骤：{step}")
            handlers = {
                "gateway_ab": do_gateway_ab,
                "confirm_b": do_confirm_b,
                "switch-client1": lambda r, p: do_client_switch(r, "client1", p),
                "switch-client2": lambda r, p: do_client_switch(r, "client2", p),
                "retire_a": do_retire_a,
            }
            result = handlers[step](rd, body.expected_phase)
            return {"ok": True, "state": full_state(), "step_result": result}

    # ---- 步骤：网关 A/B 共信 ----
    def do_gateway_ab(rd: dict[str, Any] | None, expected: str) -> dict:
        require_expected(expected, rd)
        assert rd is not None
        prior = step_record(rd, "gateway_ab")
        if prior:
            return {"replayed": True, **prior_json(prior)}
        # 1) B 材料确保已签发
        ensure_b_materials(pki)
        # 2) 网关真实切换（代理内部先持久化待生效，再排空、再换上下文）
        gw_resp = agent(
            "POST",
            f"{GATEWAY_AGENT_URL}/apply",
            {"round_id": rd["id"], "step": "gateway_ab",
             "expected_phase": PHASE_GW_AB, "trust_gens": ["A", "B"]},
        )
        # 3) 向两个客户端下发候选 B（幂等；不触碰生效证书）
        delivered = {}
        for name in CLIENT_NAMES:
            leaf_b = pki["b"]["leaves_b"][name]
            delivered[name] = agent(
                "POST",
                f"{client_agent_url(name)}/candidate-b",
                {"round_id": rd["id"], "expected_phase": PHASE_GW_AB,
                 "cert_pem": leaf_b["cert_pem"], "key_pem": leaf_b["key_pem"]},
            )
        result = {
            "ok": True,
            "replayed": bool(gw_resp.get("replayed")),
            "gateway": gw_resp.get("result", gw_resp),
            "candidate_delivered": {
                n: {"candidate_fp": r.get("candidate_fp"), "replayed": r.get("replayed", False)}
                for n, r in delivered.items()
            },
            "config_applied": True,
            "handshake_verified": False,  # 配置已写入不等于握手成功，B 握手须下一步确认
        }
        save_step(rd, "gateway_ab", "applied", PHASE_GW_AB, result)
        store.log_event(
            time.time(), "step",
            "网关已同时信任 A/B 并排空在途请求；候选 B 已下发（生效证书未动），等待 B 握手确认",
        )
        return {"replayed": False, **result}

    # ---- 步骤：确认 B 握手成功（控制服务用 canary-b 真实探测）----
    def do_confirm_b(rd: dict[str, Any] | None, expected: str) -> dict:
        require_expected(expected, rd)
        assert rd is not None
        prior = step_record(rd, "confirm_b")
        if prior:
            return {"replayed": True, **prior_json(prior)}
        ab = step_record(rd, "gateway_ab")
        if not ab:
            raise HTTPException(409, "网关尚未进入 A/B 共信，不能确认 B 握手")
        canary_b = _ck_to_obj(pki["b"]["canary_b"])
        pr = probe(canary_b, label="control-canary-b")
        if not pr["ok"]:
            result = {
                "ok": False,
                "handshake_ok": pr["handshake_ok"],
                "reason": pr["reason"] or "B 真实握手失败，禁止切换客户端",
                "probe": _probe_view(pr),
            }
            save_step(rd, "confirm_b", "failed", PHASE_GW_AB, result)
            store.log_event(time.time(), "step", f"B 握手确认失败：{result['reason']}")
            return {"replayed": False, **result}
        store.log_event(time.time(), "step", "B 真实握手确认成功，进入 CLIENT_SWITCH：可逐一切换客户端")
        result = {"ok": True, "handshake_ok": True, "probe": _probe_view(pr)}
        save_step(rd, "confirm_b", "applied", PHASE_GW_AB, result)
        store.set_phase(rd["id"], PHASE_CLIENT)
        return {"replayed": False, **result}

    # ---- 步骤：单个客户端先试 B 再切换 ----
    def do_client_switch(rd: dict[str, Any] | None, name: str, expected: str) -> dict:
        require_expected(expected, rd)
        assert rd is not None
        step = f"switch-{name}"
        prior = step_record(rd, step)
        if prior:
            return {"replayed": True, **prior_json(prior)}
        # 前置：B 握手已确认；另一个客户端的顺序不强制
        if not step_record(rd, "confirm_b"):
            raise HTTPException(409, "B 握手尚未确认，禁止切换任一客户端")
        resp = agent(
            "POST",
            f"{client_agent_url(name)}/apply",
            {"round_id": rd["id"], "step": "switch-b",
             "expected_phase": PHASE_CLIENT},
        )
        status = resp.get("status", "failed")
        result = {
            "client": name,
            "ok": status == "applied",
            "replayed": bool(resp.get("replayed")),
            "status": status,
            "config_applied": bool(resp.get("result", {}).get("config_applied")),
            "handshake_ok": bool(resp.get("result", {}).get("handshake_ok", resp.get("result", {}).get("ok"))),
            "trial": resp.get("result", {}).get("trial"),
            "reason": resp.get("result", {}).get("reason"),
            "agent_state": resp.get("state"),
        }
        save_step(rd, step, status, PHASE_CLIENT, result)
        if status != "applied":
            store.log_event(
                time.time(), "fail",
                f"客户端 {name} 候选 B 试握手失败，保持 A；轮换停在 A/B 共信阶段（A、B 客户端仍可连接）：{result['reason']}",
            )
            return {"replayed": False, **result}
        store.log_event(time.time(), "step", f"客户端 {name} 先试 B 成功后切换生效证书为 B")
        # 两个客户端均以 B 握手成功并切换后，才可退役 A
        other = [n for n in CLIENT_NAMES if n != name][0]
        other_rec = step_record(rd, f"switch-{other}")
        if other_rec and other_rec["status"] == "applied":
            store.set_phase(rd["id"], PHASE_RETIRE)
            store.log_event(time.time(), "phase", "两个客户端均已以 B 握手成功，进入 RETIRE_A")
        return {"replayed": False, **result}

    # ---- 步骤：退役 A ----
    def do_retire_a(rd: dict[str, Any] | None, expected: str) -> dict:
        require_expected(expected, rd)
        assert rd is not None
        prior = step_record(rd, "retire_a")
        if prior:
            return {"replayed": True, **prior_json(prior)}
        for name in CLIENT_NAMES:
            rec = step_record(rd, f"switch-{name}")
            if not rec or rec["status"] != "applied":
                raise HTTPException(409, f"客户端 {name} 尚未以 B 握手成功，禁止退役 A")
        gw_resp = agent(
            "POST",
            f"{GATEWAY_AGENT_URL}/apply",
            {"round_id": rd["id"], "step": "retire_a",
             "expected_phase": PHASE_RETIRE, "trust_gens": ["B"]},
        )
        # 真实验证：旧 A 新握手必须失败；B 继续成功（不能凭配置写入宣布成功）
        probe_a = probe(_ck_to_obj(pki["canary_a"]), label="control-canary-a-after-retire")
        probe_b = probe(_ck_to_obj(pki["b"]["canary_b"]), label="control-canary-b-after-retire")
        a_fails = not probe_a["ok"] and not probe_a["handshake_ok"]
        b_ok = probe_b["ok"]
        result = {
            "ok": a_fails and b_ok,
            "gateway": gw_resp.get("result", gw_resp),
            "old_a_new_handshake": {"must_fail": True, "failed_as_expected": a_fails,
                                    "handshake_ok": probe_a["handshake_ok"], "reason": probe_a["reason"]},
            "b_new_handshake": {"must_succeed": True, "ok": b_ok, "http_status": probe_b["http_status"]},
            "config_applied": True,
        }
        if not result["ok"]:
            save_step(rd, "retire_a", "failed", PHASE_RETIRE, result)
            store.log_event(time.time(), "fail", "退役 A 后验证不通过（A 未失败或 B 未成功），保留现场")
            return {"replayed": False, **result}
        save_step(rd, "retire_a", "applied", PHASE_RETIRE, result)
        store.set_phase(rd["id"], PHASE_DONE)
        store.set(K_ROUND_OPEN, None)
        store.log_event(time.time(), "done", "A 已退役：旧 A 新握手失败、B 继续成功，轮换完成")
        return {"replayed": False, **result}
    # ------------------------------------------------------- 页面手动探测
    @app.post("/api/probe/client")
    def api_probe_client(body: ClientProbeIn) -> dict:
        if body.client not in CLIENT_NAMES:
            raise HTTPException(404, "未知客户端")
        return agent(
            "POST",
            f"{client_agent_url(body.client)}/probe",
            {"gen": body.gen, "delay": body.delay},
            timeout=15,
        )

    @app.post("/api/probe/canary")
    def api_probe_canary(body: dict) -> dict:
        gen = body.get("gen", "B")
        delay = float(body.get("delay", 0.0))
        if gen == "A":
            leaf = _ck_to_obj(pki["canary_a"])
        elif gen == "B":
            if not pki.get("b"):
                raise HTTPException(409, "根 B 材料尚未在轮换发起时签发")
            leaf = _ck_to_obj(pki["b"]["canary_b"])
        else:
            raise HTTPException(400, "gen 仅支持 A / B")
        return probe(leaf, delay=delay, label=f"manual-canary-{gen}")

    # ------------------------------------------------------------ 混沌开关
    @app.post("/api/chaos")
    def api_chaos(body: ChaosIn) -> dict:
        if body.kind == "reject-b":
            if body.target != "gateway":
                raise HTTPException(400, "reject-b 只能作用于网关")
            resp = agent("POST", f"{GATEWAY_AGENT_URL}/chaos/reject-b", {"enabled": body.enabled})
            store.log_event(time.time(), "chaos", f"网关“拒绝 B 链”混沌开关 = {body.enabled}")
            return {"ok": True, "upstream": resp}
        if body.kind == "drop-receipt":
            if body.target == "gateway":
                base = GATEWAY_AGENT_URL
            elif body.target in CLIENT_NAMES:
                base = client_agent_url(body.target)
            else:
                raise HTTPException(400, "未知目标")
            resp = agent(
                "POST",
                f"{base}/chaos/drop-receipt",
                {"round_id": body.round_id, "step": body.step},
            )
            store.log_event(time.time(), "chaos", f"已在 {body.target} 布防：{body.round_id}/{body.step} 生效后丢弃一次回执")
            return {"ok": True, "upstream": resp}
        raise HTTPException(400, f"未知混沌类型：{body.kind}")

    # ---------------------------------------------------------------- 复位
    @app.post("/api/reset")
    def api_reset() -> dict:
        with lock:
            # 代理回到仅信 A / 生效 A，清除候选与混沌；使用新的一次性 round_id=0 语义在代理侧无台账冲突
            agent("POST", f"{GATEWAY_AGENT_URL}/internal/reset", {})
            for name in CLIENT_NAMES:
                agent("POST", f"{client_agent_url(name)}/internal/reset", {})
            store.clear_rounds()
            store.set(K_ROUND_OPEN, None)
            store.log_event(time.time(), "reset", "演练复位：各方回到仅根 A，B 候选与混沌开关清除")
            return {"ok": True, "state": full_state()}

    @app.get("/api/events")
    def api_events() -> dict:
        return {"events": store.list_events(50)}

    # ---------------------------------------------------------------- 页面
    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(os.path.join(os.path.dirname(__file__), "web", "index.html"))

    @app.get("/static/app.js")
    def app_js() -> FileResponse:
        return FileResponse(os.path.join(os.path.dirname(__file__), "web", "app.js"))

    @app.get("/static/style.css")
    def app_css() -> FileResponse:
        return FileResponse(os.path.join(os.path.dirname(__file__), "web", "style.css"))

    uvicorn.run(app, host="0.0.0.0", port=CONTROL_PORT)


# -------------------------------------------------------------- 序列化辅助
import json as _json  # noqa: E402


def json_loads(raw: Any) -> Any:
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return _json.loads(raw)
    except Exception:
        return raw


def prior_json(prior: dict[str, Any]) -> dict[str, Any]:
    payload = json_loads(prior["result"])
    if isinstance(payload, dict):
        return {"status": prior["status"], **payload}
    return {"status": prior["status"], "result": payload}


def _probe_view(trial: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": trial["ok"],
        "handshake_ok": trial["handshake_ok"],
        "http_status": trial["http_status"],
        "elapsed_ms": trial["elapsed_ms"],
        "reason": trial["reason"],
        "gateway": trial.get("gateway"),
    }


def _ck(ck: CertKey) -> dict[str, str]:
    return {"cert_pem": ck.cert_pem().decode(), "key_pem": ck.key_pem().decode()}


def _ck_to_obj(d: dict[str, str]) -> CertKey:
    cert = load_cert_pem(d["cert_pem"].encode())
    key = serialization.load_pem_private_key(d["key_pem"].encode(), password=None)
    return CertKey(cert=cert, key=key)
