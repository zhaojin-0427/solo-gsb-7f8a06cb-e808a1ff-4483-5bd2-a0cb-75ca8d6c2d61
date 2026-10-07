#!/usr/bin/env python3
"""按 MTLS_ROLE 启动控制服务 / 网关代理 / 客户端代理。"""
import os


def main() -> None:
    role = os.environ.get("MTLS_ROLE", "control")
    if role == "control":
        from app.control_app import main as run
    elif role == "gateway":
        from app.gateway_app import main as run
    elif role == "client":
        from app.client_app import main as run
    else:
        raise SystemExit(f"未知 MTLS_ROLE={role}")
    run()


if __name__ == "__main__":
    main()
