"""A private, per-invocation sing-box backend with no system network changes.

The readiness handshake checks the local authenticated listener. It does not
claim that the WireGuard peer is reachable, or contain traffic that ignores
the supplied proxy environment.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import time
from typing import BinaryIO
from urllib.parse import quote

from .lifecycle import finish_cleanup


class TransportError(RuntimeError):
    """A transport failure whose message does not contain credentials."""


def backend_settings(profile: dict, port: int, username: str, password: str) -> dict:
    """Build the supported sing-box 1.14 configuration from a parsed profile.

    Both endpoint bootstrap and DNS server addresses must be literal IPs. All
    destination lookups handled by sing-box use the profile's VPN DNS server;
    there is no local resolver or direct fallback in this configuration.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Proxy port must be between 1 and 65535")
    for value in (username, password):
        if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 255:
            raise ValueError("Proxy credentials must be 1 to 255 UTF-8 bytes")
    peer = profile["peer"]
    # Do not pass a hostname to a dialer that could bootstrap through normal DNS.
    peer_address = str(ipaddress.ip_address(peer["address"]))
    dns_addresses = [str(ipaddress.ip_address(value)) for value in profile["dns"]]
    if not dns_addresses:
        raise ValueError("At least one literal VPN DNS address is required")
    wireguard_peer = {
        "address": peer_address,
        "port": peer["port"],
        "public_key": peer["public_key"],
        "allowed_ips": list(peer["allowed_ips"]),
    }
    for key in ("persistent_keepalive_interval", "pre_shared_key"):
        if key in peer:
            wireguard_peer[key] = peer[key]
    dns_servers = [
        {
            "type": "udp",
            "tag": f"vpn-dns-{index}",
            "server": address,
            "server_port": 53,
            "detour": "wg",
        }
        for index, address in enumerate(dns_addresses)
    ]
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": dns_servers, "final": "vpn-dns-0", "disable_cache": True},
        "endpoints": [{
            "type": "wireguard",
            "tag": "wg",
            "system": False,
            "mtu": profile.get("mtu", 1280),
            "address": list(profile["address"]),
            "private_key": profile["private_key"],
            "peers": [wireguard_peer],
        }],
        "inbounds": [{
            "type": "mixed",
            "tag": "session-proxy",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"username": username, "password": password}],
            "set_system_proxy": False,
        }],
        "route": {"final": "wg", "default_domain_resolver": "vpn-dns-0"},
    }


def _exact(stream: socket.socket, count: int, deadline: float | None = None) -> bytes:
    data = bytearray()
    while len(data) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError("Proxy handshake deadline expired")
            stream.settimeout(remaining)
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise TransportError("Proxy closed during its handshake")
        data.extend(chunk)
    return bytes(data)


def _authenticate(stream: socket.socket, username: str, password: str, deadline: float | None = None) -> None:
    user_bytes, password_bytes = username.encode("utf-8"), password.encode("utf-8")
    if not 1 <= len(user_bytes) <= 255 or not 1 <= len(password_bytes) <= 255:
        raise TransportError("Unsupported proxy credential length")
    stream.sendall(b"\x05\x01\x02")
    if _exact(stream, 2, deadline) != b"\x05\x02":
        raise TransportError("Proxy did not require the expected authentication")
    stream.sendall(bytes([1, len(user_bytes)]) + user_bytes + bytes([len(password_bytes)]) + password_bytes)
    if _exact(stream, 2, deadline) != b"\x01\x00":
        raise TransportError("Proxy authentication failed")


def socks_connect(backend: Backend, host: str, port: int, timeout: float = 5.0) -> socket.socket:
    """Open one authenticated TCP connection to a literal destination IP."""
    ip = ipaddress.ip_address(host)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise TransportError("Unsupported destination port")
    deadline = time.monotonic() + timeout
    stream = socket.create_connection(("127.0.0.1", backend.port), timeout=timeout)
    try:
        _authenticate(stream, backend.username, backend.password, deadline)
        address_type = 1 if ip.version == 4 else 4
        stream.sendall(bytes([5, 1, 0, address_type]) + ip.packed + struct.pack("!H", port))
        response = _exact(stream, 4, deadline)
        if response[0] != 5 or response[1] != 0 or response[2] != 0:
            raise TransportError("VPN proxy rejected the TCP connection")
        if response[3] == 1:
            _exact(stream, 6, deadline)
        elif response[3] == 4:
            _exact(stream, 18, deadline)
        elif response[3] == 3:
            _exact(stream, _exact(stream, 1, deadline)[0] + 2, deadline)
        else:
            raise TransportError("VPN proxy returned an invalid address")
        return stream
    except BaseException:
        stream.close()
        raise


class Backend:
    """Own only the sing-box process and secret files for this invocation."""

    def __init__(self, profile: dict, session_dir: Path, binary: str = "sing-box"):
        self.profile = profile
        self.session_dir = Path(session_dir)
        self.binary = binary
        self.username = "invpn-" + secrets.token_hex(8)
        self.password = secrets.token_hex(24)
        self.port = 0
        self.process: subprocess.Popen | None = None
        self.path = self.session_dir / "backend.private.json"
        self.log_path = self.session_dir / "backend.private.log"
        self._log: BinaryIO | None = None
        self._owns_config = False
        self._closed = False

    def start(self) -> Backend:
        if self._closed:
            raise TransportError("A closed backend cannot be restarted")
        if self.process is not None:
            if self.process.poll() is None:
                return self
            raise TransportError("The VPN backend has exited")
        try:
            self._prepare_directory()
            version = subprocess.run(
                [self.binary, "version"], capture_output=True, text=True,
                timeout=5, check=False,
            )
            if version.returncode or not re.search(r"^sing-box version 1\.14\.\d+(?:\s|$)", version.stdout):
                raise TransportError("This implementation requires sing-box 1.14.x")
            # sing-box does not accept an already-bound listener. Readiness uses
            # random credentials to detect a competing listener after release.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
                reserved.bind(("127.0.0.1", 0))
                self.port = reserved.getsockname()[1]
            config_fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self._owns_config = True
            with os.fdopen(config_fd, "w", encoding="utf-8") as handle:
                json.dump(backend_settings(self.profile, self.port, self.username, self.password), handle)
                handle.write("\n")
            log_fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self._log = os.fdopen(log_fd, "wb")
            checked = subprocess.run(
                [self.binary, "check", "-c", str(self.path)],
                stdout=self._log, stderr=self._log, timeout=10, check=False,
            )
            if checked.returncode:
                raise TransportError("sing-box rejected the configuration; see the private backend log")
            self.process = subprocess.Popen(
                [self.binary, "run", "-c", str(self.path)],
                stdin=subprocess.DEVNULL, stdout=self._log, stderr=self._log,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise TransportError("The VPN backend exited during startup; see the private backend log")
                try:
                    with socket.create_connection(("127.0.0.1", self.port), timeout=0.25) as stream:
                        _authenticate(stream, self.username, self.password, time.monotonic() + 0.25)
                    if self.process.poll() is not None:
                        raise TransportError("The VPN backend exited during startup")
                    return self
                except (OSError, TransportError):
                    time.sleep(0.05)
            raise TransportError("The VPN backend listener did not become ready")
        except BaseException:
            self.close()
            raise

    def _prepare_directory(self) -> None:
        if self.session_dir.is_symlink():
            raise TransportError("The session directory must not be a symlink")
        self.session_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        stat = self.session_dir.stat()
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise TransportError("The session directory must be owned by you with permissions 0700")

    def proxy_environment(self) -> dict[str, str]:
        if not self.port:
            raise TransportError("Start the VPN backend before using its proxy environment")
        credentials = quote(self.username, safe="") + ":" + quote(self.password, safe="")
        http = f"http://{credentials}@127.0.0.1:{self.port}"
        socks = f"socks5h://{credentials}@127.0.0.1:{self.port}"
        result = {}
        for key, value in (("http_proxy", http), ("https_proxy", http), ("all_proxy", socks), ("no_proxy", "")):
            result[key] = value
            result[key.upper()] = value
        return result

    def close(self) -> None:
        with finish_cleanup():
            self._close_owned()

    def _close_owned(self) -> None:
        self._closed = True
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self._log is not None:
            self._log.close()
            self._log = None
        if self._owns_config:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self._owns_config = False

    def __enter__(self) -> Backend:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.close()
