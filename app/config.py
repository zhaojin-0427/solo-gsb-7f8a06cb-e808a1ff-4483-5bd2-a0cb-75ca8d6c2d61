"""演练环境中的固定常量与角色配置。"""
from __future__ import annotations

import os

# 逻辑代际（generation）名称，贯穿控制服务、网关与客户端
GEN_A = "A"
GEN_B = "B"

CLIENT_NAMES = ["client1", "client2"]

# 网关数据面（真实 mTLS 端口）与代理控制面（HTTP）端口
TLS_PORT = int(os.environ.get("TLS_PORT", "8443"))
AGENT_PORT = int(os.environ.get("AGENT_PORT", "8081"))

# 网关 TLS 主机名：网关服务端证书的 SAN 包含该名称，客户端用它做 SNI / 主机名校验
GATEWAY_HOST = os.environ.get("GATEWAY_HOST", "gateway")
GATEWAY_TLS_PORT = int(os.environ.get("GATEWAY_TLS_PORT", str(TLS_PORT)))

CONTROL_HOST = os.environ.get("CONTROL_HOST", "control")
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "8000"))

# 各代理控制面地址（Compose 内默认服务名；本地联测可用环境变量覆盖）
GATEWAY_AGENT_URL = os.environ.get("GATEWAY_AGENT_URL", "http://gateway:8081")


def client_agent_url(name: str) -> str:
    return os.environ.get(
        f"{name.upper().replace('-', '_')}_AGENT_URL",
        f"http://{name}:8081",
    )


# 网关数据面的长探测最长允许延迟（秒）：演练要求提供最长 3 秒延迟
MAX_PROBE_DELAY = 3.0

# 生成身份
ROLE = os.environ.get("MTLS_ROLE", "control")
# 客户端角色名称：client1 / client2
CLIENT_NAME = os.environ.get("CLIENT_NAME", "client1")

# 数据目录（每个容器挂载各自的持久卷）
DATA_DIR = os.environ.get("DATA_DIR", "/data")
