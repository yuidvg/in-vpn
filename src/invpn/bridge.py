"""Bounded authenticated TCP relay for the explicitly scoped macOS mode.

This module deliberately rejects UDP and general IPv6. It implements the
native Provider's existing newline JSON handshake without importing probes.
"""
from __future__ import annotations

from collections import deque
import ipaddress
import json
import secrets
import select
import socket
import threading
import time

from .transport import Backend, TransportError, socks_connect


_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_HEADER_LIMIT = 4096
_BUFFER_LIMIT = 262144


def _destination(host: object, port: object) -> tuple[str, int]:
    if not isinstance(host, str) or "%" in host:
        raise TransportError("The scoped bridge requires a literal destination")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise TransportError("The scoped bridge requires a literal destination") from None
    if address.version == 6:
        if address not in _NAT64_PREFIX:
            raise TransportError("General IPv6 forwarding is not supported in scoped mode")
        address = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise TransportError("Invalid scoped destination port")
    return str(address), port


class Bridge:
    """A localhost TCP bridge with a bounded number of active workers.

    Authentication and upstream setup have deadlines. Established streams have
    no forced lifetime; each direction drains independently on a TCP FIN.
    """

    def __init__(self, backend: Backend, *, max_connections: int = 32):
        if isinstance(max_connections, bool) or not isinstance(max_connections, int) or not 1 <= max_connections <= 256:
            raise ValueError("max_connections must be between 1 and 256")
        self.backend = backend
        self.port = 0
        self.secret = secrets.token_hex(24)
        self._closed = threading.Event()
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_connections)
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self._connections: set[socket.socket] = set()
        self._events: deque[dict] = deque(maxlen=1024)

    @property
    def events(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    def _record(self, event: dict) -> None:
        with self._lock:
            self._events.append(event)

    def start(self) -> Bridge:
        if self._closed.is_set():
            raise TransportError("A closed bridge cannot be restarted")
        if self._server is not None:
            return self
        if not self.backend.port:
            raise TransportError("Start the VPN backend before its bridge")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind(("127.0.0.1", 0))
            server.listen(32)
            server.settimeout(0.2)
            self.port = server.getsockname()[1]
            self._server = server
            self._thread = threading.Thread(target=self._accept, name="invpn-bridge", daemon=True)
            self._thread.start()
            return self
        except BaseException:
            server.close()
            raise

    def _accept(self) -> None:
        server = self._server
        assert server is not None
        while not self._closed.is_set():
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._closed.is_set() or not self._slots.acquire(blocking=False):
                client.close()
                self._record({"event": "connection_rejected", "reason": "closed_or_capacity"})
                continue
            worker = threading.Thread(target=self._serve, args=(client,), name="invpn-flow", daemon=True)
            with self._lock:
                self._connections.add(client)
                self._workers.add(worker)
            try:
                worker.start()
            except RuntimeError:
                with self._lock:
                    self._connections.discard(client)
                    self._workers.discard(worker)
                client.close()
                self._slots.release()
                self._record({"event": "connection_rejected", "reason": "worker_unavailable"})

    def _header(self, client: socket.socket) -> dict:
        deadline = time.monotonic() + 3.0
        data = bytearray()
        # Reading exactly through the newline preserves any TCP payload already
        # following the header; it is bounded by bytes and an absolute deadline.
        while len(data) < _HEADER_LIMIT:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._closed.is_set():
                raise TransportError("Bridge authentication deadline expired")
            client.settimeout(remaining)
            chunk = client.recv(1)
            if not chunk:
                raise TransportError("Bridge client closed before authentication")
            data.extend(chunk)
            if chunk == b"\n":
                try:
                    result = json.loads(data)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    raise TransportError("Invalid bridge request") from None
                if not isinstance(result, dict):
                    raise TransportError("Invalid bridge request")
                supplied = result.get("secret")
                if not isinstance(supplied, str) or not secrets.compare_digest(supplied, self.secret):
                    raise TransportError("Bridge authentication failed")
                return result
        raise TransportError("Bridge request exceeds its size limit")

    def _serve(self, client: socket.socket) -> None:
        upstream = None
        connected = False
        try:
            header = self._header(client)
            if header.get("proto") != "tcp":
                raise TransportError("Scoped transparent mode supports TCP only")
            host, port = _destination(header.get("host"), header.get("port"))
            if self._closed.is_set():
                raise TransportError("Bridge is closed")
            upstream = socks_connect(self.backend, host, port)
            with self._lock:
                self._connections.add(upstream)
            if self._closed.is_set():
                raise TransportError("Bridge is closed")
            client.settimeout(3)
            client.sendall(b"\x00")
            connected = True
            self._record({"event": "tcp_connected", "host": host, "port": port})
            sent, received = self._relay(client, upstream)
            self._record({"event": "tcp_closed", "sent_bytes": sent, "received_bytes": received})
        except (OSError, TransportError, ValueError, TypeError) as error:
            # Exception messages, request dictionaries, and raw tokens must not
            # enter diagnostic events. A rejected request receives a failure ACK.
            if not connected:
                try:
                    client.settimeout(0.2)
                    client.sendall(b"\x01")
                except OSError:
                    pass
            self._record({"event": "tcp_failed", "error": type(error).__name__, "connected": connected})
        finally:
            with self._lock:
                self._connections.discard(client)
                if upstream is not None:
                    self._connections.discard(upstream)
                self._workers.discard(threading.current_thread())
            client.close()
            if upstream is not None:
                upstream.close()
            self._slots.release()

    def _relay(self, client: socket.socket, upstream: socket.socket) -> tuple[int, int]:
        sides = (client, upstream)
        opposite = {client: upstream, upstream: client}
        # Each buffer contains data waiting to be written to its key socket.
        pending = {client: bytearray(), upstream: bytearray()}
        readable = set(sides)
        shutdown_writes: set[socket.socket] = set()
        counts = {client: 0, upstream: 0}
        for stream in sides:
            stream.setblocking(False)
        while not self._closed.is_set():
            for source in sides:
                target = opposite[source]
                if source not in readable and not pending[target] and target not in shutdown_writes:
                    try:
                        target.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    shutdown_writes.add(target)
            if not readable and not any(pending.values()):
                break
            reads = [stream for stream in readable if len(pending[opposite[stream]]) < _BUFFER_LIMIT]
            writes = [stream for stream in sides if pending[stream]]
            ready_reads, ready_writes, _ = select.select(reads, writes, [], 0.2)
            for target in ready_writes:
                try:
                    written = target.send(pending[target])
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise TransportError("TCP stream stopped accepting data")
                del pending[target][:written]
            for source in ready_reads:
                target = opposite[source]
                available = _BUFFER_LIMIT - len(pending[target])
                try:
                    chunk = source.recv(min(65536, available))
                except BlockingIOError:
                    continue
                if chunk:
                    pending[target].extend(chunk)
                    counts[source] += len(chunk)
                else:
                    readable.discard(source)
        return counts[client], counts[upstream]

    def close(self) -> None:
        self._closed.set()
        if self._server is not None:
            self._server.close()
        with self._lock:
            streams = list(self._connections)
        for stream in streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        if self._thread is not None:
            self._thread.join(timeout=1)
        # Upstream connection setup is bounded by its five second socket timeout.
        # Joining shares one deadline instead of waiting once per worker.
        deadline = time.monotonic() + 6
        while True:
            with self._lock:
                workers = list(self._workers)
            if not workers or time.monotonic() >= deadline:
                break
            for worker in workers:
                worker.join(timeout=max(0, min(0.2, deadline - time.monotonic())))

    def __enter__(self) -> Bridge:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.close()
