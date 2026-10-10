"""Loopback protocol tests; no VPN profiles, native settings or external hosts."""
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from invpn.bridge import Bridge
from invpn.transport import TransportError


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return bytes(data)


class SocksFixture:
    """A fake authenticated SOCKS server that responds only after request FIN."""

    def __init__(self, *, reject_connect=False):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(16)
        self.server.settimeout(0.1)
        self.backend = SimpleNamespace(port=self.server.getsockname()[1], username="fixture-user", password="fixture-password")
        self.reject_connect = reject_connect
        self.stopped = threading.Event()
        self.finished = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.workers = []
        self.destinations = []
        self.requests = []
        self.failures = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                stream, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.connections.add(stream)
            worker = threading.Thread(target=self.serve, args=(stream,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, stream):
        try:
            stream.settimeout(5)
            if exact(stream, 3) != b"\x05\x01\x02":
                raise AssertionError("Bridge did not demand SOCKS username/password authentication")
            stream.sendall(b"\x05\x02")
            version, length = exact(stream, 2)
            username = exact(stream, length)
            password = exact(stream, exact(stream, 1)[0])
            if version != 1 or username != self.backend.username.encode() or password != self.backend.password.encode():
                stream.sendall(b"\x01\x01")
                return
            stream.sendall(b"\x01\x00")
            request = exact(stream, 10)
            if request[:4] != b"\x05\x01\x00\x01":
                raise AssertionError("Bridge did not request literal IPv4 TCP CONNECT")
            with self.lock:
                self.destinations.append((socket.inet_ntoa(request[4:8]), struct.unpack("!H", request[8:])[0]))
            stream.sendall(bytes([5, 4 if self.reject_connect else 0, 0, 1]) + socket.inet_aton("127.0.0.1") + b"\x00\x01")
            if self.reject_connect:
                return
            data = bytearray()
            while True:
                chunk = stream.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
            with self.lock:
                self.requests.append(bytes(data))
            stream.sendall(bytes(data)[::-1] + b"response-after-fin")
            stream.shutdown(socket.SHUT_WR)
        except (EOFError, OSError):
            pass  # Client/bridge cleanup can intentionally terminate a fixture.
        except AssertionError as error:
            with self.lock:
                self.failures.append(str(error))
        finally:
            stream.close()
            with self.lock:
                self.connections.discard(stream)
            self.finished.set()

    def close(self):
        self.stopped.set()
        self.server.close()
        self.thread.join(timeout=1)
        with self.lock:
            streams = list(self.connections)
        for stream in streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        for worker in self.workers:
            worker.join(timeout=1)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = SocksFixture()
        self.bridge = Bridge(self.fixture.backend, max_connections=2).start()

    def tearDown(self):
        self.bridge.close()
        self.fixture.close()
        self.assertEqual(self.fixture.failures, [])
        self.assertFalse(self.bridge._workers)

    def connect(self):
        stream = socket.create_connection(("127.0.0.1", self.bridge.port), timeout=3)
        stream.settimeout(5)
        return stream

    def header(self, *, host="192.0.2.1", port=4444, proto="tcp", secret=None):
        return json.dumps({"secret": self.bridge.secret if secret is None else secret, "proto": proto, "host": host, "port": port}).encode() + b"\n"

    def test_half_close_drains_backpressure_and_preserves_payload_following_header(self):
        payload = bytes(range(256)) * 2048  # Exceeds the bridge's per-direction buffer.
        with self.connect() as stream:
            stream.sendall(self.header() + payload[:73])
            self.assertEqual(exact(stream, 1), b"\x00")
            stream.sendall(payload[73:])
            stream.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                chunk = stream.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
        self.assertEqual(response, payload[::-1] + b"response-after-fin")
        self.assertTrue(self.fixture.finished.wait(timeout=1))
        self.assertEqual(self.fixture.requests, [payload])
        self.assertEqual(self.fixture.destinations, [("192.0.2.1", 4444)])
        self.assertNotIn(self.bridge.secret, json.dumps(self.bridge.events))
        self.assertNotIn(self.fixture.backend.password, json.dumps(self.bridge.events))

    def test_exact_well_known_nat64_prefix_is_translated_to_ipv4(self):
        with self.connect() as stream:
            stream.sendall(self.header(host="64:ff9b::c000:201"))
            self.assertEqual(exact(stream, 1), b"\x00")
            stream.shutdown(socket.SHUT_WR)
            self.assertEqual(exact(stream, len(b"response-after-fin")), b"response-after-fin")
        self.assertTrue(self.fixture.finished.wait(timeout=1))
        self.assertEqual(self.fixture.destinations, [("192.0.2.1", 4444)])

    def test_udp_general_ipv6_hostnames_and_invalid_ports_are_rejected_before_socks(self):
        for arguments in (
            {"proto": "udp"}, {"proto": "unknown"}, {"host": "2001:db8::1"},
            {"host": "64:ff9b:1::c000:201"}, {"host": "example.com"},
            {"host": "fe80::1%en0"}, {"port": 0}, {"port": 65536}, {"port": True}, {"port": "4444"},
        ):
            with self.subTest(arguments=arguments), self.connect() as stream:
                stream.sendall(self.header(**arguments))
                self.assertEqual(exact(stream, 1), b"\x01")
        self.assertEqual(self.fixture.destinations, [])

    def test_wrong_bridge_authentication_has_no_upstream_attempt_or_secret_event(self):
        with self.connect() as stream:
            stream.sendall(self.header(secret="invalid-token"))
            self.assertEqual(exact(stream, 1), b"\x01")
        self.assertEqual(self.fixture.destinations, [])
        self.assertNotIn("invalid-token", json.dumps(self.bridge.events))
        self.assertNotIn(self.bridge.secret, json.dumps(self.bridge.events))

    def test_malformed_and_oversized_headers_are_rejected(self):
        for request in (b"not-json\n", b"[]\n", b"{\"secret\": 12}\n", b"x" * 4096):
            with self.subTest(length=len(request)), self.connect() as stream:
                stream.sendall(request)
                self.assertEqual(exact(stream, 1), b"\x01")
        self.assertEqual(self.fixture.destinations, [])

    def test_wrong_backend_authentication_does_not_acknowledge_a_connection(self):
        self.bridge.close()
        wrong = SimpleNamespace(port=self.fixture.backend.port, username="fixture-user", password="wrong-backend-password")
        self.bridge = Bridge(wrong).start()
        with self.connect() as stream:
            stream.sendall(self.header())
            self.assertEqual(exact(stream, 1), b"\x01")
        self.assertTrue(self.fixture.finished.wait(timeout=1))
        self.assertEqual(self.fixture.destinations, [])
        self.assertNotIn(wrong.password, json.dumps(self.bridge.events))

    def test_backend_connect_failure_does_not_acknowledge_success(self):
        self.fixture.reject_connect = True
        with self.connect() as stream:
            stream.sendall(self.header())
            self.assertEqual(exact(stream, 1), b"\x01")
        self.assertTrue(self.fixture.finished.wait(timeout=1))
        self.assertEqual(self.fixture.requests, [])

    def test_capacity_and_absolute_header_deadline_bound_stalled_clients(self):
        self.bridge.close()
        self.bridge = Bridge(self.fixture.backend, max_connections=1).start()
        with self.connect() as first:
            first.sendall(b"{")
            deadline = time.monotonic() + 1
            while not self.bridge._workers and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(self.bridge._workers)
            with self.connect() as second:
                self.assertEqual(second.recv(1), b"")
            started = time.monotonic()
            self.assertEqual(exact(first, 1), b"\x01")
            self.assertLess(time.monotonic() - started, 3.5)
        self.assertTrue(any(event.get("reason") == "closed_or_capacity" for event in self.bridge.events))
        self.assertEqual(self.fixture.destinations, [])

    def test_close_interrupts_active_streams_and_is_idempotent(self):
        with self.connect() as stream:
            stream.sendall(self.header())
            self.assertEqual(exact(stream, 1), b"\x00")
            self.bridge.close()
            try:
                self.assertEqual(stream.recv(1), b"")
            except ConnectionResetError:
                pass
        self.bridge.close()
        self.assertFalse(self.bridge._workers)
        with self.assertRaises(TransportError):
            self.bridge.start()

    def test_constructor_and_missing_backend_listener_reject_invalid_usage(self):
        for maximum in (0, 257, True, "2"):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                Bridge(self.fixture.backend, max_connections=maximum)
        with self.assertRaises(TransportError):
            Bridge(SimpleNamespace(port=0)).start()


if __name__ == "__main__":
    unittest.main()
