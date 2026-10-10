"""Pinning a packaged backend must preserve the user's command resolution."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from invpn import cli
from invpn.launcher import LaunchError


class BackendSelectionTests(unittest.TestCase):
    def test_default_uses_existing_path_without_mutating_environment(self):
        with patch.dict(os.environ, {"PATH": "/user/tools"}, clear=True), \
             patch.object(cli.shutil, "which", return_value="/user/tools/sing-box") as lookup:
            original = dict(os.environ)
            self.assertEqual(cli._backend_binary(), "/user/tools/sing-box")
            lookup.assert_called_once_with("sing-box")
            self.assertEqual(dict(os.environ), original)

    def test_absolute_backend_override_leaves_command_path_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backend = root / "packaged-sing-box"
            backend.write_text("#!/bin/sh\nexit 0\n")
            backend.chmod(0o700)
            command = root / "user-tool"
            command.write_text("#!/bin/sh\nexit 17\n")
            command.chmod(0o700)
            with patch.dict(os.environ, {"INVPN_SING_BOX": str(backend), "PATH": str(root),
                                         "PYTHONPATH": "/user/python", "PYTHONNOUSERSITE": "user-value"}, clear=True):
                original = dict(os.environ)
                self.assertEqual(cli._backend_binary(), str(backend))
                self.assertEqual(cli._command(["user-tool"], "proxy"), [str(command)])
                self.assertEqual(dict(os.environ), original)

    def test_invalid_override_does_not_fall_back_to_an_unintended_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            non_executable = root / "non-executable"
            non_executable.touch()
            for invalid in ("", "sing-box", str(root), str(root / "absent"), str(non_executable)):
                with self.subTest(override=invalid), \
                     patch.dict(os.environ, {"INVPN_SING_BOX": invalid}), \
                     patch.object(cli.shutil, "which") as lookup, \
                     self.assertRaises(LaunchError):
                    cli._backend_binary()
                lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
