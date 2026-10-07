"""网关 mTLS 数据面：真实 TLS 监听器。

关键点：
- 每个连接在握手时绑定当时的 SSLContext（信任集）；切换只影响之后的新握手。
- 切换时先冻结 accept 循环，等待"已建立"的在途探测请求全部完成（最长排空等待），
  再原子替换 SSLContext；切换期间到达的新 TCP 连接在替换后才握手。
- verify_callback 支持演练混沌开关：拒绝由根 B 签发的叶子证书（模拟 B 不被信任）。
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import threading
import time
from typing import Any

from cryptography import x509

from .config import GATEWAY_HOST, MAX_PROBE_DELAY
from .pki import cert_fingerprint


class GatewayDataServer(threading.Thread):
    def __init__(self, host: str = "0.0.0.0", port: int = 8443, runtime_dir: str = "/data/runtime"):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.runtime_dir = runtime_dir
        os.makedirs(runtime_dir, exist_ok=True)

        self._ctx: ssl.SSLContext | None = None
        self._trust_gens: list[str] = []
        self._server_materials: tuple[bytes, bytes, dict[str, bytes]] | None = None
        self._ctx_lock = threading.RLock()
        self._swapping = threading.Event()
        self._cond = threading.Condition()
        self._active = 0  # 已完成握手、请求处理中的连接数
        self._served = 0
        self.reject_b = False  # 混沌开关：拒绝 B 签发的客户端证书
        self._started_ok = threading.Event()
        self.start_error: Exception | None = None

    def wait_started(self, timeout: float = 5.0) -> bool:
        return self._started_ok.wait(timeout) and self.start_error is None

    # ---------- 上下文 ----------
    def _effective_ca_pems(self, trusted_ca_pems: dict[str, bytes]) -> list[bytes]:
        """混沌开关 reject_b 开启时，从信任库中移除 B——B 链在真实握手校验中失败。"""
        gens = list(trusted_ca_pems.keys())
        if self.reject_b:
            gens = [g for g in gens if g != "B"]
        return [trusted_ca_pems[g] for g in gens]

    def _build_context(
        self,
        server_cert_pem: bytes,
        server_key_pem: bytes,
        trusted_ca_pems: dict[str, bytes],
    ) -> ssl.SSLContext:
        cert_path = os.path.join(self.runtime_dir, "server_cert.pem")
        key_path = os.path.join(self.runtime_dir, "server_key.pem")
        ca_path = os.path.join(self.runtime_dir, "client_roots.pem")
        ca_list = self._effective_ca_pems(trusted_ca_pems)
        with open(cert_path, "wb") as fh:
            fh.write(server_cert_pem)
        with open(key_path, "wb") as fh:
            fh.write(server_key_pem)
        with open(ca_path, "wb") as fh:
            for pem in ca_list:
                fh.write(pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        if ca_list:
            ctx.load_verify_locations(cafile=ca_path)
        # CERT_REQUIRED + 空信任库：任何客户端证书都无法通过校验
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        return ctx

    def configure_initial(
        self,
        server_cert_pem: bytes,
        server_key_pem: bytes,
        trusted_ca_pems: dict[str, bytes],
    ) -> None:
        with self._ctx_lock:
            self._server_materials = (server_cert_pem, server_key_pem, dict(trusted_ca_pems))
            self._ctx = self._build_context(server_cert_pem, server_key_pem, trusted_ca_pems)

    def set_reject_b(self, enabled: bool) -> None:
        """切换混沌开关并立即重建上下文：排空与信任切换语义一致，仅影响之后的新握手。"""
        with self._cond:
            self._swapping.set()
            with self._ctx_lock:
                self.reject_b = enabled
                if getattr(self, "_server_materials", None):
                    cert_pem, key_pem, cas = self._server_materials
                    self._ctx = self._build_context(cert_pem, key_pem, cas)
            self._swapping.clear()
            self._cond.notify_all()

    def switch_trust(
        self,
        server_cert_pem: bytes,
        server_key_pem: bytes,
        trusted_ca_pems: list[bytes]
        | dict[str, bytes],
        *,
        drain_timeout: float = MAX_PROBE_DELAY + 2.0,
    ) -> dict[str, Any]:
        """排空在途请求后替换信任集；返回排空观测信息。"""
        if isinstance(trusted_ca_pems, dict):
            ca_map = dict(trusted_ca_pems)
        else:
            # 兼容有序列表入参（配合当前生效代际名）
            ca_map = {g: pem for g, pem in zip(self._trust_gens, trusted_ca_pems)}
        drained: list[int] = []
        with self._cond:
            self._swapping.set()
            deadline = time.monotonic() + drain_timeout
            while self._active > 0 and time.monotonic() < deadline:
                drained.append(self._active)
                self._cond.wait(timeout=min(0.1, deadline - time.monotonic()))
            inflight_at_swap = self._active
            with self._ctx_lock:
                self._trust_gens = list(ca_map.keys())
                self._server_materials = (server_cert_pem, server_key_pem, ca_map)
                self._ctx = self._build_context(server_cert_pem, server_key_pem, ca_map)
            self._swapping.clear()
            self._cond.notify_all()
        return {
            "inflight_before_swap": (drained[0] if drained else 0),
            "inflight_at_swap": inflight_at_swap,
            "swapped_at": time.time(),
        }

    def stats(self) -> dict[str, Any]:
        with self._cond:
            return {"active": self._active, "served": self._served, "swapping": self._swapping.is_set()}

    # ---------- 监听 ----------
    def run(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(32)
            sock.settimeout(0.5)
        except Exception as exc:  # noqa: BLE001
            self.start_error = exc
            self._started_ok.set()
            return
        self._started_ok.set()
        while True:
            try:
                raw, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(raw,), daemon=True
            ).start()

    def _handle(self, raw: socket.socket) -> None:
        # 切换期间：暂缓握手，使新连接按新信任集裁决
        with self._cond:
            while self._swapping.is_set():
                self._cond.wait(timeout=0.2)
            with self._ctx_lock:
                ctx = self._ctx
        if ctx is None:
            raw.close()
            return
        raw.settimeout(8.0)
        tls: ssl.SSLSocket
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            try:
                raw.close()
            except OSError:
                pass
            return

        # 握手已建立：计入在途请求，切换须等待我们完成
        with self._cond:
            self._active += 1
        try:
            self._serve(tls)
        finally:
            with self._cond:
                self._active -= 1
                self._served += 1
                self._cond.notify_all()
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tls.close()

    def _serve(self, tls: ssl.SSLSocket) -> None:
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 65536:
                    return
            head = data.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
            lines = head.split("\r\n")
            method, path, _ = (lines[0].split(" ", 2) + ["", "", ""])[:3]
            if method != "GET":
                self._send(tls, 405, {"error": "method not allowed"})
                return
            delay = 0.0
            if "?" in path:
                route, query = path.split("?", 1)
                for pair in query.split("&"):
                    if pair.startswith("delay="):
                        try:
                            delay = float(pair.split("=", 1)[1])
                        except ValueError:
                            delay = 0.0
            else:
                route = path
            delay = max(0.0, min(delay, MAX_PROBE_DELAY))
            if delay:
                time.sleep(delay)
            if route not in ("/probe", "/healthz"):
                self._send(tls, 404, {"error": "not found"})
                return

            peer_der = tls.getpeercert(binary_form=True)
            peer_cert = x509.load_der_x509_certificate(peer_der) if peer_der else None
            issuer_cn = ""
            if peer_cert is not None:
                try:
                    issuer_cn = peer_cert.issuer.get_attributes_for_oid(
                        x509.oid.NameOID.COMMON_NAME
                    )[0].value
                except IndexError:
                    pass
            body = {
                "ok": True,
                "client_authenticated": peer_cert is not None,
                "client_subject": peer_cert.subject.rfc4514_string() if peer_cert else None,
                "client_fingerprint": cert_fingerprint(peer_cert) if peer_cert else None,
                "issuer_cn": issuer_cn,
                "server_host": GATEWAY_HOST,
                "delay": delay,
                "served_at": time.time(),
            }
            self._send(tls, 200, body)
        except (ssl.SSLError, OSError, ConnectionError):
            return

    @staticmethod
    def _send(tls: ssl.SSLSocket, status: int, payload: dict[str, Any]) -> None:
        reason = {200: "OK", 404: "Not Found", 405: "Method Not Allowed"}.get(status, "OK")
        body = json.dumps(payload).encode()
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        tls.sendall(head + body)
