"""The public CLI must expose its limits before executing user commands."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "in-vpn"


class CLIContractTests(unittest.TestCase):
    def setUp(self):
        if not CLI.exists():
            self.skipTest("public CLI is not present yet")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profiles = self.root / "profiles"
        self.profiles.mkdir(mode=0o700)
        private = base64.b64encode(bytes(range(32))).decode()
        public = base64.b64encode(bytes(range(32, 64))).decode()
        profile = self.profiles / "vpn1.conf"
        profile.write_text(
            f"[Interface]\nPrivateKey = {private}\nAddress = 10.77.0.2/32\nDNS = 10.77.0.53\n"
            f"[Peer]\nPublicKey = {public}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.10:51820\n"
        )
        profile.chmod(0o600)
        self.marker = self.root / "command-started"
        self.env = dict(os.environ)

    def run_cli(self, *arguments):
        return subprocess.run(
            [str(CLI), *map(str, arguments)],
            cwd=ROOT,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def assert_refused_before_command(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists(), "CLI executed the command before refusing the unsupported mode")
        self.assertTrue(result.stderr.strip(), "refusal must explain the reason on stderr")
        self.assertNotIn("Traceback", result.stderr, "an implementation crash is not a valid contract refusal")

    def test_help_is_available_without_platform_setup(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("in-vpn", result.stdout)

    def test_capabilities_are_machine_readable_without_running_a_command(self):
        result = self.run_cli("capabilities", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertIsInstance(document, dict)
        self.assertTrue(document, "empty capabilities would conceal the unresolved product requirements")
        self.assertEqual(document["status"], "partial")
        self.assertEqual(document["default_mode"], "isolated")
        self.assertFalse(document["modes"]["isolated"]["available"])
        self.assertFalse(document["modes"]["proxy"]["direct_traffic_blocked"])
        self.assertTrue(document["modes"]["transparent"]["experimental"])
        self.assertFalse(document["modes"]["transparent"]["direct_traffic_blocked"])
        for name in ("transparent_all_destinations", "descendant_transparent_routing", "standard_dns_isolation", "crash_containment", "transparent_udp_quic_icmp"):
            with self.subTest(capability=name):
                self.assertEqual(document["capabilities"][name], "unavailable")
        self.assertFalse(self.marker.exists())

    def test_default_contract_refuses_unimplemented_full_protection(self):
        result = self.run_cli("--config-dir", self.profiles, "vpn1", "/usr/bin/touch", self.marker)
        self.assert_refused_before_command(result)

    def test_unknown_profile_does_not_execute_command(self):
        result = self.run_cli("--config-dir", self.profiles, "missing", "/usr/bin/touch", self.marker)
        self.assert_refused_before_command(result)

    def test_transparent_mode_requires_explicit_experimental_opt_in(self):
        result = self.run_cli("--config-dir", self.profiles, "--mode", "transparent", "vpn1", "/usr/bin/touch", self.marker)
        self.assert_refused_before_command(result)
        self.assertIn("experimental", result.stderr.lower())

    def test_transparent_mode_requires_a_declared_destination(self):
        result = self.run_cli("--config-dir", self.profiles, "--mode", "transparent", "--experimental", "vpn1", "/usr/bin/touch", self.marker)
        self.assert_refused_before_command(result)
        self.assertIn("destination", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
