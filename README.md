# 本地 mTLS 信任根轮换演练（根 A → 根 B）

一个完全本地化的 mTLS 信任根（CA）轮换演练环境：**Python / FastAPI / cryptography / SQLite / 原生 JavaScript**，
每个参与方都是独立容器、独立持久卷，全部握手都是**真实 TLS 握手**（不是“配置写好了就当成功”）。

## 一条命令启动

```bash
docker compose up --build
```

打开浏览器访问：**http://localhost:8000**

停止并清空全部演练数据（四个独立卷）：

```bash
docker compose down -v
```

## 参与方（四个独立容器 / 四个独立 SQLite 卷）

| 服务 | 角色 | 持久化内容 |
| --- | --- | --- |
| `control` | 控制服务 + 演练页面（:8000） | PKI 权威材料、轮次/阶段、每步回执、事件日志 |
| `gateway` | mTLS TLS 网关（真实数据面 :8443 + 控制面 :8081） | 当前信任代际集合、网关证书、混沌开关、步骤台账 |
| `client1` | 独立客户端代理（:8081） | 本进程**生效证书/私钥与代际**、候选 B、步骤台账 |
| `client2` | 独立客户端代理（:8081） | 同上，完全独立 |

- 固定的 `Server-CA` 只签发网关服务端证书（SAN 含 `gateway`/`localhost`）。
- 客户端叶子证书由独立的信任根签发：初始全部由 **根 A** 签发；轮换时由 **根 B** 签发。
- 根 B 的客户端证书在“发起轮换”时**只签发一次**，之后任何重放、重启、回执丢失都复用同一批证书，绝不重签。

## 轮换阶段机

```
INIT ──发起轮换──▶ GATEWAY_AB ──确认 B 握手成功──▶ CLIENT_SWITCH ──两个客户端均以 B 成功──▶ RETIRE_A ──▶ DONE
                   ▲ 任一步真实握手失败则停在此阶段（A/B 共信，A、B 客户端仍都可连接）
```

页面上每一步都是一个按钮，逐步推进：

1. **发起根 B 轮换**：签发 B（仅一次）；**网关先同时信任 A/B**，切换时先排空已建立的探测请求；
   两个客户端只收到“候选 B”，生效证书不动。此步结果里明确标注
   `handshake_verified=false`——配置已写入 ≠ 握手成功。
2. **确认 B 握手成功**：控制服务用独立的“金丝雀 B”证书对网关发起**真实 TLS 握手**；
   只有握手 + HTTP 请求都成功，才进入客户端切换阶段。
3. **客户端 1 / 2 分别切换**：客户端代理用本进程保存的**候选 B 先试真实握手**：
   - 失败 → 保持生效证书 A，本步记为终态失败，轮换停在 A/B 共信阶段；
   - 成功 → 才把生效证书切换为 B。两个客户端互不影响。
4. **退役 A**：只有两个客户端都以 B 握手成功后才允许执行。网关切到仅信任 B，随后控制服务
   **真实验证**：旧 A 叶子的新握手必须失败、B 叶子的新握手继续成功；两者同时满足才标记 DONE。

### 协议规则（均已实现并验证）

- **每步必须携带 `expected_phase`**；阶段不匹配返回 `409`，过期阶段不得推进。
- **重复同一步只返回原结果**：代理侧与控制服务侧都有按 `(轮次, 步骤)` 的持久台账，
  不重复切换、不重复试握手、不重复签发。
- **并发再发起一轮返回 `409`**：已有进行中的轮次时禁止新开。
- **切换时序**：网关 `switch_trust` 先置“切换中”标志（期间到达的新 TCP 连接暂不握手），
  等待所有**已完成握手的在途请求**结束（最长等待 5s，探测延迟上限 3s），再原子替换 SSLContext；
  之后的新握手一律按新信任集裁决。
- **状态分开持久化**：控制服务与每个代理各自写自己的 SQLite 卷。任何一步命令生效前后
  `docker compose restart`（或 `stop` 后 `start`），都按**代理实际生效代际与真实握手结果**恢复：
  已生效但控制侧没回执的步骤，重试时代理返回原结果、控制侧补记，不会跳步也不会重签 B。

## 页面能看到什么

- 各方证书/根的 **SHA-256 指纹**（页面显示前 16 位）、网关信任代际与根指纹、两个客户端的
  生效代际/生效指纹/候选 B 指纹。
- 当前阶段、轮次号、每步状态（已生效 / 失败 / 待生效）与**失败的真实原因**（如
  `tlsv1 alert unknown ca`）。
- “手动真实握手探测”：可选择由控制服务金丝雀或某个**客户端用本进程保存的证书**发起真实握手，
  代际可选生效证书 / A / B，延迟可选 0–3 秒（用于观察切换时在途请求被排空）。
  输出严格区分 `handshake_ok`（TLS 握手）与最终 HTTP 结果。

## 演练开关（混沌注入）

- **网关开始拒绝 B 链**：在 A/B 共信期间开启后，信任库实际剔除 B，B 的新握手在 TLS 层真实失败。
  可以分别制造“步骤 2 确认 B 失败”和“步骤 3 某客户端试 B 失败、停在 A”两种现场；
  解除开关后，已记录终态失败的步骤不会偷偷重跑，按复位后新开一轮处理。
- **生效后丢弃一次回执**：可对网关的 `gateway_ab` 或某客户端的 `switch-b` 布防。
  代理先把生效状态落盘，再把这一次 HTTP 回执变成 503——此时控制侧没有回执、代理侧已生效；
  直接再点一次同一步即可安全恢复（代理返回原结果，不重复执行）。

## 失败后如何继续

- 轮换停在 A/B 共信阶段时，页面上“复位演练”会让各方回到仅信任根 A、客户端恢复初始 A 证书
  （复用、不重签），并清掉候选 B、台账与混沌开关；之后可重新发起一轮。
- PKI 材料（含只签一次的 B）始终保留在控制服务卷中，复位不等于重签。

## 本地不用 Docker 运行（开发用）

```bash
pip install -r requirements.txt
# 需要四个独立 DATA_DIR，并让 client/gateway 能访问 control:8000、能连到 gateway:8443
# 参考 docker-compose.yml 中的环境变量（MTLS_ROLE / CLIENT_NAME / *_HOST / *_PORT / DATA_DIR）
MTLS_ROLE=control DATA_DIR=./.data/control python run.py
MTLS_ROLE=gateway DATA_DIR=./.data/gateway GATEWAY_HOST=localhost CONTROL_HOST=localhost python run.py
MTLS_ROLE=client CLIENT_NAME=client1 DATA_DIR=./.data/c1 AGENT_PORT=8082 CONTROL_HOST=localhost GATEWAY_HOST=localhost python run.py
MTLS_ROLE=client CLIENT_NAME=client2 DATA_DIR=./.data/c2 AGENT_PORT=8083 CONTROL_HOST=localhost GATEWAY_HOST=localhost python run.py
```

## 主要文件

- `app/control_app.py`：控制服务、阶段机、回执台账、状态聚合与页面 API
- `app/gateway_app.py` / `app/gateway_data.py`：网关控制面与真实 mTLS 数据面（动态信任集、排空切换）
- `app/client_app.py`：客户端代理（生效证书持久化、候选 B 先试后切）
- `app/tls_probe.py`：真实 TLS 握手探测（含 TLS 1.3 客户端证书拒绝告警处理）
- `app/pki.py`：cryptography 两级 PKI（Server-CA / 根 A / 根 B）
- `app/store.py`：各自独立的 SQLite 持久化
- `app/web/`：原生 JavaScript 演练页面
