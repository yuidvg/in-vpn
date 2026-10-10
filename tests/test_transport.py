"""Backend configuration, privacy, failure cleanup and local readiness checks."""
import base64
import copy
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from invpn.transport import Backend, TransportError, backend_settings


def synthetic_profile():
    """Public test keys and a localhost peer; never load an installed VPN profile."""
    return {
        "private_key": base64.b64encode(bytes(range(32))).decode("ascii"),
        "address": ["10.77.0.2/32"],
        "dns": ["10.77.0.53", "10.77.0.54"],
        "mtu": 1280,
        "peer": {
            "address": "127.0.0.1", "port": 59999,
            "public_key": base64.b64encode(bytes(range(32, 64))).decode("ascii"),
            "allowed_ips": ["0.0.0.0/0"],
            "persistent_keepalive_interval": 0,
        },
    }


def supported_version():
    return subprocess.CompletedProcess(["sing-box", "version"], 0, "sing-box version 1.14.1\n", "")


class BackendSettingsTests(unittest.TestCase):
    def test_all_resolvers_and_default_traffic_use_userspace_wireguard(self):
        profile = synthetic_profile()
        profile["peer"]["pre_shared_key"] = base64.b64encode(bytes(32)).decode("ascii")
        previous = copy.deepcopy(profile)
        settings = backend_settings(profile, 12345, "user", "password")
        self.assertEqual(profile, previous)
        self.assertFalse(settings["endpoints"][0]["system"])
        self.assertEqual(settings["route"]["final"], "wg")
        self.assertEqual(settings["route"]["default_domain_resolver"], settings["dns"]["final"])
        self.assertTrue(settings["dns"]["disable_cache"])
        self.assertEqual([server["server"] for server in settings["dns"]["servers"]], profile["dns"])
        self.assertTrue(all(server["detour"] == "wg" and server["type"] == "udp" for server in settings["dns"]["servers"]))
        self.assertNotIn("outbounds", settings)
        self.assertNotIn('"type": "direct"', json.dumps(settings))
        self.assertNotIn('"type": "local"', json.dumps(settings))
        self.assertEqual(settings["endpoints"][0]["peers"][0]["pre_shared_key"], profile["peer"]["pre_shared_key"])

    def test_listener_is_local_authenticated_and_does_not_set_system_proxy(self):
        settings = backend_settings(synthetic_profile(), 12345, "user", "password")
        inbound = settings["inbounds"][0]
        self.assertEqual(inbound["type"], "mixed")
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["users"], [{"username": "user", "password": "password"}])
        self.assertFalse(inbound["set_system_proxy"])

    def test_hostnames_cannot_bootstrap_through_normal_dns(self):
        for field in ("peer", "dns"):
            profile = synthetic_profile()
            if field == "peer":
                profile["peer"]["address"] = "vpn.example.com"
            else:
                profile["dns"] = ["dns.example.com"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                backend_settings(profile, 12345, "user", "password")
        profile = synthetic_profile()
        profile["dns"] = []
        with self.assertRaises(ValueError):
            backend_settings(profile, 12345, "user", "password")

    def test_invalid_listener_or_authentication_parameters_are_rejected(self):
        for port in (0, 65536, True, "12345"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                backend_settings(synthetic_profile(), port, "user", "password")
        for username, password in (("", "password"), ("user", ""), ("u" * 256, "password"), ("user", "é" * 128)):
            with self.subTest(lengths=(len(username), len(password))), self.assertRaises(ValueError):
                backend_settings(synthetic_profile(), 12345, username, password)


class BackendLifecycleTests(unittest.TestCase):
    def test_proxy_environment_carries_remote_dns_and_clears_bypass(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = Backend(synthetic_profile(), Path(directory))
            with self.assertRaises(TransportError):
                backend.proxy_environment()
            backend.port = 12345
            environment = backend.proxy_environment()
            self.assertEqual(environment["no_proxy"], "")
            self.assertEqual(environment["NO_PROXY"], "")
            for name in ("http_proxy", "https_proxy", "all_proxy"):
                self.assertEqual(environment[name], environment[name.upper()])
                self.assertIn(backend.username, environment[name])
                self.assertIn(backend.password, environment[name])
            self.assertTrue(environment["all_proxy"].startswith("socks5h://"))
            self.assertTrue(environment["https_proxy"].startswith("http://"))

    def test_configuration_failure_removes_secret_file_and_keeps_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            backend = Backend(synthetic_profile(), path)
            failure = subprocess.CompletedProcess(["sing-box", "check"], 1, "", "")
            with patch("invpn.transport.subprocess.run", side_effect=[supported_version(), failure]), patch("invpn.transport.subprocess.Popen") as spawn:
                with self.assertRaises(TransportError) as caught:
                    backend.start()
            spawn.assert_not_called()
            self.assertNotIn(backend.password, str(caught.exception))
            self.assertNotIn(backend.profile["private_key"], str(caught.exception))
            self.assertFalse(backend.path.exists())
            self.assertEqual(backend.log_path.stat().st_mode & 0o777, 0o600)
            backend.close()  # Repeated cleanup is safe.
            with self.assertRaises(TransportError):
                backend.start()

    def test_unsupported_binary_version_creates_no_secret_files(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = Backend(synthetic_profile(), Path(directory))
            version = subprocess.CompletedProcess(["sing-box", "version"], 0, "sing-box version 1.15.0\n", "")
            with patch("invpn.transport.subprocess.run", return_value=version):
                with self.assertRaises(TransportError):
                    backend.start()
            self.assertFalse(backend.path.exists())
            self.assertFalse(backend.log_path.exists())

    def test_existing_secret_file_is_not_overwritten_or_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = Backend(synthetic_profile(), Path(directory))
            backend.path.write_text("existing-owned-session\n")
            with patch("invpn.transport.subprocess.run", return_value=supported_version()):
                with self.assertRaises(FileExistsError):
                    backend.start()
            self.assertEqual(backend.path.read_text(), "existing-owned-session\n")

    def test_session_directory_must_be_private_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public"
            public.mkdir(mode=0o755)
            public.chmod(0o755)
            linked = root / "linked"
            linked.symlink_to(public, target_is_directory=True)
            for candidate in (public, linked):
                with self.subTest(candidate=candidate.name), self.assertRaises(TransportError):
                    Backend(synthetic_profile(), candidate).start()


@unittest.skipUnless(shutil.which("sing-box"), "sing-box is not installed")
class LocalSingBoxIntegrationTests(unittest.TestCase):
    def test_real_configuration_readiness_authentication_and_cleanup(self):
        # Readiness only. The peer is localhost and keepalive is zero; this test
        # performs no CONNECT, domain lookup, or external VPN transaction.
        version = subprocess.run(["sing-box", "version"], capture_output=True, text=True, timeout=5)
        if not version.stdout.startswith("sing-box version 1.14."):
            self.skipTest("Integration requires sing-box 1.14.x")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with Backend(synthetic_profile(), path) as backend:
                self.assertIsNone(backend.process.poll())
                self.assertGreater(backend.port, 0)
                self.assertEqual(backend.path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(backend.log_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.stat().st_uid, os.getuid())
                settings = json.loads(backend.path.read_text())
                self.assertEqual(settings["route"]["final"], "wg")
                self.assertEqual(settings["inbounds"][0]["users"][0]["password"], backend.password)
            self.assertIsNotNone(backend.process.poll())
            self.assertFalse(backend.path.exists())
            self.assertTrue(backend.log_path.exists())

    def test_domain_lookup_and_http_are_forwarded_through_local_wireguard(self):
        """Exercise backend DNS routing using two actual local WireGuard peers."""
        version = subprocess.run(["sing-box", "version"], capture_output=True, text=True, timeout=5)
        if not version.stdout.startswith("sing-box version 1.14."):
            self.skipTest("Integration requires sing-box 1.14.x")
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(0.1)
        http_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        http_server.bind(("127.0.0.1", 0))
        http_server.listen(4)
        http_server.settimeout(0.1)
        stopped = threading.Event()
        dns_queries = []
        http_requests = []
        fixture_errors = []
        name = "controlled.invpn.test"

        def dns_receiver():
            while not stopped.is_set():
                try:
                    request, source = udp.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    if len(request) < 17:
                        raise ValueError("short DNS request")
                    index, labels = 12, []
                    while request[index]:
                        length = request[index]
                        index += 1
                        labels.append(request[index:index + length].decode("ascii"))
                        index += length
                    question_end = index + 5
                    query_type, query_class = struct.unpack("!HH", request[index + 1:question_end])
                    dns_queries.append((".".join(labels), query_type))
                    if query_class != 1:
                        raise ValueError("unexpected DNS class")
                    answer = b""
                    if query_type == 1:
                        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton("10.77.0.99")
                    response = request[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
                    response += request[12:question_end] + answer
                    udp.sendto(response, source)
                except (ValueError, IndexError, struct.error, OSError) as error:
                    if not stopped.is_set():
                        fixture_errors.append(type(error).__name__)

        def http_receiver():
            while not stopped.is_set():
                try:
                    stream, _ = http_server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with stream:
                    try:
                        stream.settimeout(3)
                        request = bytearray()
                        while b"\r\n\r\n" not in request and len(request) < 8192:
                            chunk = stream.recv(4096)
                            if not chunk:
                                break
                            request.extend(chunk)
                        http_requests.append(bytes(request))
                        body = b"vpn-dns-resolved"
                        stream.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                    except OSError as error:
                        if not stopped.is_set():
                            fixture_errors.append(type(error).__name__)

        threads = [threading.Thread(target=dns_receiver, daemon=True), threading.Thread(target=http_receiver, daemon=True)]
        for thread in threads:
            thread.start()
        server_process = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pairs = []
                for _ in range(2):
                    output = subprocess.check_output(["sing-box", "generate", "wg-keypair"], text=True, timeout=5)
                    pairs.append(dict(line.split(": ", 1) for line in output.strip().splitlines()))
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    peer_port = reservation.getsockname()[1]
                server_settings = {
                    "log": {"level": "warn"},
                    "endpoints": [{"type": "wireguard", "tag": "test-peer", "system": False,
                                   "listen_port": peer_port, "address": ["10.77.0.1/24"],
                                   "private_key": pairs[0]["PrivateKey"],
                                   "peers": [{"public_key": pairs[1]["PublicKey"], "allowed_ips": ["10.77.0.2/32"]}]}],
                    # Direct is confined to the synthetic server's receivers;
                    # the product client's configuration has only WireGuard.
                    "outbounds": [{"type": "direct", "tag": "test-receiver"}],
                    "route": {"rules": [
                        {"network": "udp", "action": "route", "outbound": "test-receiver", "override_address": "127.0.0.1", "override_port": udp.getsockname()[1]},
                        {"network": "tcp", "action": "route", "outbound": "test-receiver", "override_address": "127.0.0.1", "override_port": http_server.getsockname()[1]},
                    ], "final": "test-receiver"},
                }
                server_path = root / "server.private.json"
                descriptor = os.open(server_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as config_file:
                    json.dump(server_settings, config_file)
                log_path = root / "server.private.log"
                log_descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(log_descriptor, "wb") as server_log:
                    checked = subprocess.run(["sing-box", "check", "-c", str(server_path)], stdout=server_log, stderr=server_log, timeout=5)
                    self.assertEqual(checked.returncode, 0, "Synthetic WireGuard server configuration was rejected")
                    server_process = subprocess.Popen(["sing-box", "run", "-c", str(server_path)], stdin=subprocess.DEVNULL, stdout=server_log, stderr=server_log)
                    time.sleep(0.1)
                    self.assertIsNone(server_process.poll(), "Synthetic WireGuard server exited during startup")
                    profile = synthetic_profile()
                    profile["private_key"] = pairs[1]["PrivateKey"]
                    profile["dns"] = ["10.77.0.53"]
                    profile["peer"].update({"port": peer_port, "public_key": pairs[0]["PublicKey"]})
                    with Backend(profile, root / "client") as backend:
                        connection = http.client.HTTPConnection("127.0.0.1", backend.port, timeout=5)
                        credentials = base64.b64encode(f"{backend.username}:{backend.password}".encode()).decode()
                        try:
                            connection.request("GET", f"http://{name}:8090/probe", headers={"Proxy-Authorization": "Basic " + credentials})
                            response = connection.getresponse()
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.read(), b"vpn-dns-resolved")
                        finally:
                            connection.close()
                    self.assertIn((name, 1), dns_queries)
                    self.assertTrue(http_requests)
                    self.assertIn(b"GET /probe HTTP/1.1", http_requests[0])
                    self.assertEqual(fixture_errors, [])
        finally:
            if server_process is not None and server_process.poll() is None:
                server_process.terminate()
                try:
                    server_process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server_process.kill()
                    server_process.wait(timeout=2)
            stopped.set()
            udp.close()
            http_server.close()
            for thread in threads:
                thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
