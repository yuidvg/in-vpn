"""Regression checks for cancellation cleanup and identity-wide exclusivity."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from invpn import cli
from invpn.profiles import ProfileError, ProfileStore, parse_wireguard
from invpn.transport import Backend


def profile_text():
    private = base64.b64encode(bytes(range(32))).decode()
    public = base64.b64encode(bytes(range(32, 64))).decode()
    return (
        f"[Interface]\nPrivateKey = {private}\nAddress = 10.77.0.2/32\nDNS = 10.77.0.53\n"
        f"[Peer]\nPublicKey = {public}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.10:51820\n"
    )


HOLDING_CLI = """
import os, pathlib, sys, time
from types import SimpleNamespace
from unittest.mock import patch
from invpn import cli
root = pathlib.Path(sys.argv[1])
class OwnedBackend:
    def __init__(self, *args, **kwargs):
        self.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
    def __enter__(self):
        (root / 'owned').write_text('owned')
        return self
    def proxy_environment(self):
        (root / 'ready').write_text('ready')
        deadline = time.monotonic() + 10
        while not (root / 'release').exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('fixture release deadline expired')
            time.sleep(0.01)
        return {}
    def __exit__(self, *args):
        (root / 'owned').unlink(missing_ok=True)
        (root / 'closed').write_text('closed')
with patch.object(cli, 'LOCK_DIRECTORY', root / 'locks'), patch('invpn.transport.Backend', OwnedBackend):
    result = cli.main(['--config-dir', str(root / 'config1'), '--state-dir', str(root / 'state1'), '--mode', 'proxy', 'vpn1', '/usr/bin/touch', str(root / 'first-command')])
raise SystemExit(result)
"""


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config1"
        self.config.mkdir(mode=0o700)
        self.write_profile(self.config, "vpn1")
        self.marker = self.root / "command-started"
        self.owned = self.root / "owned-resource"
        self.events = []
        self.addCleanup(patch.stopall)
        patch.object(cli, "LOCK_DIRECTORY", self.root / "locks").start()
        patch.dict(os.environ, {"INVPN_SESSION": ""}).start()

    def write_profile(self, directory, name):
        path = directory / f"{name}.conf"
        path.write_text(profile_text())
        path.chmod(0o600)

    def backend(self, on_proxy=None, on_close=None):
        owner = self

        class OwnedBackend:
            def __init__(self, *args, **kwargs):
                self.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)

            def __enter__(self):
                owner.owned.write_text("owned")
                owner.events.append("entered")
                return self

            def proxy_environment(self):
                if on_proxy:
                    on_proxy()
                return {}

            def __exit__(self, *args):
                owner.events.append("close-start")
                if on_close:
                    on_close()
                owner.owned.unlink()
                owner.events.append("close-finished")

        return OwnedBackend

    def invoke(self, config=None, state=None, profile="vpn1"):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = cli.main([
                "--config-dir", str(config or self.config), "--state-dir", str(state or self.root / "state1"),
                "--mode", "proxy", profile, "/usr/bin/touch", str(self.marker),
            ])
        self.assertNotIn("Traceback", stderr.getvalue())
        return result

    def assert_locks_released(self):
        paths = list((self.root / "locks").glob("*.lock"))
        self.assertTrue(paths)
        for path in paths:
            with cli._lock(path):
                pass

    def test_preparation_term_closes_owned_resources_before_command(self):
        def cancel_preparation():
            self.assertTrue(self.owned.exists())
            self.assertFalse(self.marker.exists())
            os.kill(os.getpid(), signal.SIGTERM)

        with patch("invpn.transport.Backend", self.backend(on_proxy=cancel_preparation)):
            result = self.invoke()
        self.assertEqual(result, 143)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.owned.exists())
        self.assertEqual(self.events, ["entered", "close-start", "close-finished"])
        self.assert_locks_released()
        state = json.loads(next((self.root / "state1/sessions").glob("*/state.json")).read_text())
        self.assertEqual(state["state"], "cancelled")

    def test_first_cleanup_term_finishes_the_current_and_remaining_cleanup(self):
        with patch("invpn.transport.Backend", self.backend(on_close=lambda: os.kill(os.getpid(), signal.SIGTERM))):
            result = self.invoke()
        self.assertEqual(result, 143)
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.owned.exists())
        self.assertEqual(self.events[-2:], ["close-start", "close-finished"])
        self.assert_locks_released()

    def test_repeated_cleanup_term_does_not_skip_owned_cleanup(self):
        def repeated_term():
            for _ in range(3):
                os.kill(os.getpid(), signal.SIGTERM)
                self.events.append("cleanup-continued")

        with patch("invpn.transport.Backend", self.backend(on_close=repeated_term)):
            result = self.invoke()
        self.assertEqual(result, 143)
        self.assertFalse(self.owned.exists())
        self.assertEqual(self.events.count("cleanup-continued"), 3)
        self.assertEqual(self.events[-1], "close-finished")
        self.assert_locks_released()

    def test_backend_start_failure_defers_first_cleanup_term_until_resources_close(self):
        backend = Backend(parse_wireguard(profile_text()), self.root / "failed-backend", binary="synthetic-sing-box")
        events = []
        log_handles = []

        class Process:
            returncode = None

            def poll(self):
                return self.returncode

            def terminate(self):
                events.append("terminate")
                log_handles.append(backend._log)
                os.kill(os.getpid(), signal.SIGTERM)
                events.append("terminate-continued")

            def wait(self, timeout=None):
                self.returncode = 0
                events.append("wait-finished")
                return 0

        process = Process()
        # The product writes its real private files and reaches a local listener
        # failure. The process fixture injects TERM during the ensuing cleanup;
        # no WireGuard peer or native configuration is started.
        with patch("invpn.transport.subprocess.run", side_effect=[SimpleNamespace(returncode=0, stdout="sing-box version 1.14.1\n"), SimpleNamespace(returncode=0)]), \
             patch("invpn.transport.subprocess.Popen", return_value=process), \
             patch("invpn.transport.socket.create_connection", side_effect=OSError("synthetic listener unavailable")), \
             patch("invpn.transport.time.monotonic", side_effect=[0.0, 1.0, 6.0]), \
             patch("invpn.transport.time.sleep"), \
             cli._cleanup_signals(), \
             self.assertRaises(cli.SessionCancelled) as cancellation:
            backend.start()
        self.assertEqual(cancellation.exception.number, signal.SIGTERM)
        self.assertEqual(events, ["terminate", "terminate-continued", "wait-finished"])
        self.assertEqual(process.returncode, 0)
        self.assertTrue(log_handles[0].closed)
        self.assertIsNone(backend._log)
        self.assertFalse(backend.path.exists())
        self.assertFalse(self.marker.exists())

    def test_identity_lock_survives_different_profile_config_and_state_names(self):
        second_config = self.root / "config2"
        second_config.mkdir(mode=0o700)
        self.write_profile(second_config, "another-name")
        environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"), INVPN_SESSION="")
        process = subprocess.Popen([sys.executable, "-c", HOLDING_CLI, str(self.root)], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "ready").exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue((self.root / "ready").exists(), "first CLI did not acquire its profile lock")

            class ForbiddenBackend:
                def __init__(self, *args, **kwargs):
                    raise AssertionError("second backend started despite an active identical WireGuard identity")

            with patch("invpn.transport.Backend", ForbiddenBackend):
                result = self.invoke(config=second_config, state=self.root / "state2", profile="another-name")
            self.assertEqual(result, 78)
            self.assertFalse(self.marker.exists())
            self.assertTrue((self.root / "owned").exists())
        finally:
            (self.root / "release").write_text("release")
            try:
                _, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=3)
                raise
        self.assertEqual(process.returncode, 0, stderr)
        self.assertTrue((self.root / "first-command").exists())
        self.assertTrue((self.root / "closed").exists())
        self.assert_locks_released()

    def test_management_names_cannot_be_imported_as_profiles(self):
        source = self.root / "source.conf"
        source.write_text(profile_text())
        store = ProfileStore(self.config)
        for name in ("doctor", "status", "capabilities", "profiles"):
            with self.subTest(name=name), self.assertRaises(ProfileError):
                store.import_file(name, source)
            self.assertFalse((self.config / f"{name}.conf").exists())


if __name__ == "__main__":
    unittest.main()
