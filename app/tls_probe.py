"""真实 mTLS 探测：用指定客户端证书/私钥向网关发起 TLS 握手并完成一次 HTTP 请求。

- 握手在请求任何 HTTP 数据前完成，握手失败与"配置已写入"严格区分。
- verify 失败原因从客户端 OpenSSL 错误中提取。
- delay 由网关按请求路径处理，最长 3 秒，用于观察切换期间在途请求。
"""
from __future__ import annotations

import socket
import ssl
import time
from typing import Any

from cryptography import x509

from .config import GATEWAY_HOST, GATEWAY_TLS_PORT, MAX_PROBE_DELAY
from .pki import cert_fingerprint, load_cert_pem


def _client_verify_error(exc: ssl.SSLError | OSError) -> str:
    text = str(exc)
    # OpenSSL 校验失败通常带 "certificate verify failed"
    if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text:
        return "网关不信任该客户端证书（certificate verify failed）"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"服务端证书校验失败：{exc.verify_message}"
    return text.splitlines()[0][:200]


def _is_client_cert_alert(exc: BaseException) -> bool:
    """TLS 1.3 下服务器对客户端证书的拒绝以 post-handshake alert 送达，
    可能在 wrap_socket / send / recv 任一阶段暴露，本质都是客户端不被信任。"""
    text = str(exc)
    return any(k in text for k in (
        "UNKNOWN_CA", "unknown ca", "BAD_CERTIFICATE", "bad certificate",
        "CERTIFICATE_UNKNOWN", "certificate unknown",
        "CERTIFICATE_VERIFY_FAILED", "certificate verify failed",
    ))


def tls_probe(
    client_cert_pem: bytes,
    client_key_pem: bytes,
    server_ca_pem: bytes,
    *,
    host: str = GATEWAY_HOST,
    port: int = GATEWAY_TLS_PORT,
    delay: float = 0.0,
    timeout: float = 6.0,
    label: str = "",
) -> dict[str, Any]:
    """发起一次真实握手；返回结构化结果，不抛异常。"""
    delay = max(0.0, min(float(delay), MAX_PROBE_DELAY))
    result: dict[str, Any] = {
        "label": label,
        "delay": delay,
        "ok": False,
        "handshake_ok": False,
        "http_status": None,
        "peer_fingerprint": None,
        "reason": None,
        "gateway": None,
        "elapsed_ms": None,
    }
    started = time.monotonic()
    try:
        leaf = load_cert_pem(client_cert_pem)
        result["client_fingerprint"] = cert_fingerprint(leaf)
    except Exception:
        result["client_fingerprint"] = None

    import tempfile, os

    with tempfile.TemporaryDirectory() as tmp:
        cert_path = os.path.join(tmp, "cert.pem")
        key_path = os.path.join(tmp, "key.pem")
        ca_path = os.path.join(tmp, "ca.pem")
        with open(cert_path, "wb") as fh:
            fh.write(client_cert_pem)
        with open(key_path, "wb") as fh:
            fh.write(client_key_pem)
        with open(ca_path, "wb") as fh:
            fh.write(server_ca_pem)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=ca_path)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            try:
                sock = ctx.wrap_socket(raw, server_hostname=host)
            except (ssl.SSLError, OSError) as exc:
                if _is_client_cert_alert(exc):
                    result["reason"] = "网关不信任该客户端证书（" + str(exc).splitlines()[0][:160] + "）"
                else:
                    result["reason"] = _client_verify_error(exc)
                result["elapsed_ms"] = round(
                    (time.monotonic() - started) * 1000, 1
                )
                return result
            result["handshake_ok"] = True
            try:
                peer_der = sock.getpeercert(binary_form=True)
                if peer_der:
                    peer_cert = x509.load_der_x509_certificate(peer_der)
                    result["peer_fingerprint"] = cert_fingerprint(peer_cert)
                path = f"/probe?delay={delay:g}"
                req = (
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                    "Connection: close\r\n\r\n"
                )
                try:
                    sock.sendall(req.encode())
                except (ssl.SSLError, OSError) as exc:
                    if _is_client_cert_alert(exc):
                        result["handshake_ok"] = False
                        result["reason"] = "网关不信任该客户端证书（" + str(exc).splitlines()[0][:160] + "）"
                        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
                        return result
                    raise
                buf = b""
                sock.settimeout(timeout + MAX_PROBE_DELAY)
                while True:
                    try:
                        chunk = sock.recv(4096)
                    except (ssl.SSLError, OSError) as exc:
                        if _is_client_cert_alert(exc):
                            result["handshake_ok"] = False
                            result["reason"] = "网关不信任该客户端证书（" + str(exc).splitlines()[0][:160] + "）"
                            result["elapsed_ms"] = round(
                                (time.monotonic() - started) * 1000, 1
                            )
                            return result
                        raise
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 1_000_000:
                        break
            finally:
                sock.close()
        finally:
            try:
                raw.close()
            except OSError:
                pass

    head, _, body = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = status_line.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        result["http_status"] = int(parts[1])
    import json as _json

    try:
        gw = _json.loads(body)
        result["gateway"] = gw
        result["ok"] = result["http_status"] == 200 and bool(
            gw.get("client_authenticated")
        )
    except Exception:
        result["ok"] = result["http_status"] == 200
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
    return result
