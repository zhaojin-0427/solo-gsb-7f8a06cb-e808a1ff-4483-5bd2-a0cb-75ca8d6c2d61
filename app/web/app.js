"use strict";

let STATE = null;
let busy = false;

const $ = (id) => document.getElementById(id);
const short = (fp) => (fp ? String(fp).slice(0, 16) : "—");

async function api(path, body) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const err = new Error(
      (data && (data.detail || (data.upstream && data.upstream.detail))) ||
        `HTTP ${resp.status}`
    );
    err.status = resp.status;
    err.body = data;
    throw err;
  }
  return data;
}

function expectedPhase() {
  return STATE ? STATE.phase : "INIT";
}

async function doAction(act) {
  if (busy) return;
  busy = true;
  try {
    let res;
    switch (act) {
      case "start":
        res = await api("/api/rotate/start", { expected_phase: "INIT" });
        break;
      case "confirm_b":
        res = await api("/api/rotate/step", { step: "confirm_b", expected_phase: "GATEWAY_AB" });
        break;
      case "switch-client1":
        res = await api("/api/rotate/step", { step: "switch-client1", expected_phase: "CLIENT_SWITCH" });
        break;
      case "switch-client2":
        res = await api("/api/rotate/step", { step: "switch-client2", expected_phase: "CLIENT_SWITCH" });
        break;
      case "retire_a":
        res = await api("/api/rotate/step", { step: "retire_a", expected_phase: "RETIRE_A" });
        break;
      case "reset":
        res = await api("/api/reset", {});
        $("probe-out").textContent = "已复位：各方回到仅根 A，B 材料保留不重签。";
        break;
      case "reject-on":
        res = await api("/api/chaos", { target: "gateway", kind: "reject-b", enabled: true });
        break;
      case "reject-off":
        res = await api("/api/chaos", { target: "gateway", kind: "reject-b", enabled: false });
        break;
      case "arm-gateway-ab":
        res = await api("/api/chaos", {
          target: "gateway", kind: "drop-receipt",
          round_id: (STATE && STATE.round_id ? STATE.round_id : 0) + 1,
          step: "gateway_ab",
        });
        break;
      case "arm-client1":
        res = await api("/api/chaos", { target: "client1", kind: "drop-receipt", round_id: STATE.round_id, step: "switch-b" });
        break;
      case "arm-client2":
        res = await api("/api/chaos", { target: "client2", kind: "drop-receipt", round_id: STATE.round_id, step: "switch-b" });
        break;
      case "probe": {
        const actor = $("probe-actor").value;
        const gen = $("probe-gen").value;
        const delay = parseFloat($("probe-delay").value || "0");
        const endpoint = actor === "canary"
          ? "/api/probe/canary"
          : "/api/probe/client";
        const payload = actor === "canary" ? { gen: gen === "effective" ? "A" : gen, delay }
          : { client: actor, gen, delay };
        res = await api(endpoint, payload);
        renderProbe(res);
        await refresh();
        busy = false;
        return;
      }
      default:
        return;
    }
    if (res && res.state) STATE = res.state;
    else await refreshState();
    render();
  } catch (exc) {
    await refreshState();
    render();
    showError(exc);
  } finally {
    busy = false;
  }
}

function showError(exc) {
  const box = $("fail-banner");
  let msg = exc.message || String(exc);
  if (exc.body && exc.body.upstream && exc.body.upstream.actually_applied) {
    msg += "（代理实际已生效：重放该步即可拿到原结果）";
  }
  box.textContent = "⚠ " + msg;
  box.classList.remove("hidden");
  setTimeout(() => box.classList.add("hidden"), 6000);
}

function renderProbe(p) {
  const verdict = p.handshake_ok ? (p.ok ? "握手+请求成功 ✅" : "握手成功但请求未通过 ⚠") : "TLS 握手失败 ❌";
  const lines = [
    `结论：${verdict}`,
    `代际：${p.gen || "?"}  发起方：${p.label || ""}  延迟：${p.delay ?? 0}s`,
    `handshake_ok=${p.handshake_ok}  http_status=${p.http_status ?? "—"}  耗时=${p.elapsed_ms ?? "?"}ms`,
  ];
  if (p.reason) lines.push(`失败原因：${p.reason}`);
  if (p.gateway) {
    lines.push(`网关回显：客户端=${p.gateway.client_subject}`);
    lines.push(`          指纹=${short(p.gateway.client_fingerprint)} 签发者=${p.gateway.issuer_cn}`);
  }
  if (p.peer_fingerprint) lines.push(`网关证书指纹：${short(p.peer_fingerprint)}`);
  $("probe-out").textContent = lines.join("\n");
}

function stepMap() {
  const m = {};
  (STATE.steps || []).forEach((s) => { m[s.step] = s; });
  return m;
}

function render() {
  if (!STATE) return;
  const phase = STATE.phase;
  const phaseEl = $("phase");
  phaseEl.textContent = phase;
  phaseEl.className = "phase" + (phase === "DONE" ? " done" : STATE.last_failure ? " fail" : "");
  $("round").textContent = STATE.round_id ? `轮次 #${STATE.round_id}` : "尚未发起轮换";

  const f = STATE.fingerprints || {};
  $("fp-root-a").textContent = short(f.root_a);
  $("fp-root-b").textContent = short(f.root_b);
  $("fp-server-ca").textContent = short(f.server_ca);
  $("fp-server").textContent = short(f.server);
  $("fp-canary-a").textContent = short(f.canary_a);
  $("fp-canary-b").textContent = f.canary_b ? short(f.canary_b) : "轮换发起时签发";

  const gw = STATE.agents && STATE.agents.gateway;
  if (gw && !gw.unreachable) {
    $("gw-trust").textContent = (gw.trust_gens || []).join(" + ");
    const fps = gw.trusted_fps || {};
    $("gw-fps").textContent = (gw.trust_gens || []).map((g) => `${g}:${short(fps[g])}`).join("  ");
    const dp = gw.data_plane || {};
    $("gw-stats").textContent = `${dp.active ?? "?"} / ${dp.served ?? "?"}${dp.swapping ? "（切换排空中）" : ""}`;
    $("gw-rejectb").textContent = gw.chaos_reject_b ? "开（B 会被拒）" : "关";
  } else {
    $("gw-trust").textContent = "代理不可达";
  }

  ["client1", "client2"].forEach((name, i) => {
    const n = i + 1;
    const c = STATE.agents && STATE.agents.clients && STATE.agents.clients[name];
    if (c && !c.unreachable) {
      $(`c${n}-gen`).textContent = c.effective_gen;
      $(`c${n}-fp`).textContent = short(c.effective_fp);
      $(`c${n}-cand`).textContent = c.candidate_gen ? `${c.candidate_gen}: ${short(c.candidate_fp)}` : "无";
      $(`c${n}-line`).textContent = c.status_line || `生效 ${c.effective_gen}`;
    } else {
      $(`c${n}-gen`).textContent = "代理不可达";
    }
  });

  // 步骤状态与按钮可用性
  const steps = stepMap();
  const hasFailure = !!STATE.last_failure;
  document.querySelectorAll("#steps li").forEach((li) => {
    const key = li.dataset.step;
    const st = li.querySelector(".step-status");
    const rec = steps[key];
    st.className = "step-status";
    if (rec) {
      st.classList.add(rec.status);
      let detail = "";
      if (rec.status === "applied") detail = "已生效（重放只返回原结果）";
      else if (rec.status === "failed") detail = "失败：" + ((rec.result || {}).reason || "见日志");
      else detail = "待生效/处理中";
      st.textContent = detail;
    } else {
      st.textContent = "未执行";
    }
    li.classList.toggle("done", !!rec && rec.status === "applied");
  });

  setEnabled("start", phase === "INIT");
  setEnabled("confirm_b", phase === "GATEWAY_AB" && !!steps.gateway_ab && !steps.confirm_b && !hasFailure);
  setEnabled("switch-client1", phase === "CLIENT_SWITCH" && !steps["switch-client1"]);
  setEnabled("switch-client2", phase === "CLIENT_SWITCH" && !steps["switch-client2"]);
  setEnabled("retire_a", phase === "RETIRE_A" && !steps.retire_a);

  if (STATE.last_failure) {
    const b = $("fail-banner");
    b.textContent = `⛔ 步骤 ${STATE.last_failure.step} 失败，轮换停在 ${phase}：${STATE.last_failure.reason || ""}（可复位后重开一轮）`;
    b.classList.remove("hidden");
  }

  $("events").textContent = (STATE.events || [])
    .map((e) => `[${new Date(e.at * 1000).toLocaleTimeString()}] ${e.kind}  ${e.message}`)
    .join("\n");
}

function setEnabled(act, ok) {
  const btn = document.querySelector(`[data-act="${act}"]`);
  if (btn) btn.disabled = !ok;
}

async function refreshState() {
  const data = await fetch("/api/state").then((r) => r.json());
  STATE = data;
}

async function refresh() {
  await refreshState();
  render();
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-act]");
  if (btn && !btn.disabled) doAction(btn.dataset.act);
});

refresh().catch((e) => { $("phase").textContent = "控制服务启动中…"; console.error(e); });
setInterval(() => refresh().catch(() => {}), 2000);
