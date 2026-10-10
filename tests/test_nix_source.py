"""Nix staging never needs to ingest the workspace's private test artifacts."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch


HELPER = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/nix-package"))
stage_sources = HELPER["stage_sources"]
replace_lock = HELPER["replace_lock"]
nix_command = HELPER["nix_command"]
main = HELPER["main"]
StagingError = HELPER["StagingError"]
LOCK = {"version": 7, "root": "root", "nodes": {"root": {}}}


class NixSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repository"
        self.destination = Path(self.temporary.name) / "stage"
        self.allowed = {
            "flake.nix": "{ outputs = inputs: {}; }\n",
            "flake.lock": json.dumps(LOCK),
            "pyproject.toml": "[project]\nname = 'invpn'\n",
            "LICENSE": "MIT License\n",
            "packaging/nix/package.nix": "{}: null\n",
            "src/invpn/__init__.py": "\n",
            "src/invpn/cli.py": "def main(): return 0\n",
            "bin/in-vpn": "#!/usr/bin/env python3\n",
            "scripts/nix-package": "#!/usr/bin/env python3\n",
            "tests/test_cli.py": "def test_cli(): pass\n",
        }
        for relative, content in self.allowed.items():
            self.write(relative, content)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_only_allowlisted_files_enter_stage(self):
        marker = "PRIVATE-SECRET-MUST-NEVER-ENTER-NIX"
        for relative in (".local/secrets/wg.conf", ".local/build/certificate.p12", "README.md",
                         "macos/Host/Host.swift", "experiments/secret.py", "src/invpn/__pycache__/key.pyc",
                         "packaging/nix/private.pem", "tests/credentials.json", "scripts/install-cli"):
            self.write(relative, marker)
        # Alias is deliberately excluded even though it is a symlink.
        (self.root / "bin/invpn").symlink_to(self.root / ".local/secrets/wg.conf")
        manifest = stage_sources(self.root, self.destination)
        self.assertEqual(manifest, tuple(sorted(self.allowed)))
        staged_files = {str(path.relative_to(self.destination)) for path in self.destination.rglob("*") if path.is_file()}
        self.assertEqual(staged_files, set(self.allowed))
        self.assertFalse(any(marker.encode() in path.read_bytes() for path in self.destination.rglob("*") if path.is_file()))

    def test_included_file_symlink_is_rejected_without_copying_secret(self):
        secret = self.write(".local/secrets/private", "DO-NOT-COPY")
        (self.root / "src/invpn/escape.py").symlink_to(secret)
        with self.assertRaises(StagingError):
            stage_sources(self.root, self.destination)
        self.assertFalse((self.destination / "src/invpn/escape.py").exists())

    def test_included_directory_symlink_is_rejected(self):
        original = self.root / "src/invpn"
        renamed = self.root / ".local/private-source"
        renamed.parent.mkdir()
        original.rename(renamed)
        original.symlink_to(renamed, target_is_directory=True)
        with self.assertRaises(StagingError):
            stage_sources(self.root, self.destination)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Requires POSIX FIFO support")
    def test_special_source_file_is_rejected_without_reading(self):
        os.mkfifo(self.root / "tests/test_private.py")
        with self.assertRaises(StagingError):
            stage_sources(self.root, self.destination)

    def test_missing_lock_is_allowed_only_for_lock_operation(self):
        (self.root / "flake.lock").unlink()
        with self.assertRaises(StagingError):
            stage_sources(self.root, self.destination)
        second = self.destination.with_name("lock-stage")
        manifest = stage_sources(self.root, second, require_lock=False)
        self.assertNotIn("flake.lock", manifest)

    def test_lock_destination_symlink_cannot_overwrite_secret(self):
        secret = self.write(".local/secrets/private", "PRESERVE")
        destination = self.root / "flake.lock"
        destination.unlink()
        destination.symlink_to(secret)
        generated = Path(self.temporary.name) / "generated.lock"
        generated.write_text(json.dumps(LOCK))
        with self.assertRaises(StagingError):
            replace_lock(self.root, generated)
        self.assertEqual(secret.read_text(), "PRESERVE")
        self.assertTrue(destination.is_symlink())

    def test_lock_update_requires_version_seven_and_is_atomic(self):
        generated = Path(self.temporary.name) / "generated.lock"
        generated.write_text(json.dumps(dict(LOCK, version=6)))
        previous = (self.root / "flake.lock").read_bytes()
        with self.assertRaises(StagingError):
            replace_lock(self.root, generated)
        self.assertEqual((self.root / "flake.lock").read_bytes(), previous)
        updated = dict(LOCK, nodes={"root": {"inputs": {}}})
        generated.write_text(json.dumps(updated))
        replace_lock(self.root, generated)
        self.assertEqual(json.loads((self.root / "flake.lock").read_bytes()), updated)
        self.assertEqual(list(self.root.glob(".flake.lock-*")), [])

    def test_generated_lock_symlink_is_refused(self):
        original = self.root / "flake.lock"
        generated = Path(self.temporary.name) / "generated.lock"
        generated.symlink_to(original)
        with self.assertRaises(StagingError):
            replace_lock(self.root, generated)
        self.assertEqual(json.loads(original.read_bytes()), LOCK)

    def test_run_separator_and_build_link_choice_are_preserved(self):
        command = nix_command("run", self.destination, ["--", "--version"])
        self.assertEqual(command[-2:], ["--", "--version"])
        self.assertIn("--no-write-lock-file", command)
        build = nix_command("build", self.destination, [])
        self.assertIn("--no-link", build)
        explicit = nix_command("build", self.destination, ["--out-link", "chosen-result"])
        self.assertNotIn("--no-link", explicit)
        self.assertEqual(explicit[-2:], ["--out-link", "chosen-result"])
        with self.assertRaises(StagingError):
            nix_command("build", self.destination, ["--out-link", "one", "--out-link=two"])
        check = nix_command("check", self.destination, [])
        self.assertIn("--no-write-lock-file", check)

    def test_extra_installables_and_source_overrides_are_refused(self):
        unsafe = (["."], [str(self.root)], ["path:" + str(self.root)],
                  ["--override-input", "nixpkgs", "path:" + str(self.root)],
                  ["--write-lock-file"], ["--recreate-lock-file"],
                  ["--output-lock-file", "private.lock"])
        for action in ("build", "run", "check", "lock"):
            for arguments in unsafe:
                with self.subTest(action=action, arguments=arguments), self.assertRaises(StagingError):
                    nix_command(action, self.destination, arguments)
        # After run's separator these are the launched program's arguments.
        command = nix_command("run", self.destination, ["--", "--override-input", "."])
        self.assertEqual(command[-3:], ["--", "--override-input", "."])

    def test_short_out_link_and_safe_flags(self):
        command = nix_command("build", self.destination,
                              ["--print-out-paths", "-L", "--offline", "-o", "chosen-result"])
        self.assertNotIn("--no-link", command)
        self.assertEqual(command[-2:], ["-o", "chosen-result"])
        with self.assertRaises(StagingError):
            nix_command("build", self.destination, ["-o", "one", "--out-link=two"])
        with self.assertRaises(StagingError):
            nix_command("build", self.destination, ["--out-link", "--override-input"])

    def test_main_preserves_run_program_separator(self):
        # Drive the parser and executor together; a direct nix_command test
        # would miss argparse consuming the first separator.
        helper_file = self.root / "scripts/nix-package"
        with patch.dict(main.__globals__, {"__file__": str(helper_file)}), \
                patch.object(HELPER["subprocess"], "run") as execute:
            execute.return_value.returncode = 0
            self.assertEqual(main(["run", "--", "--version"]), 0)
        command = execute.call_args.args[0]
        self.assertEqual(command[-2:], ["--", "--version"])
        self.assertIn("--no-write-lock-file", command)
        flake_argument = next(value for value in command if value.endswith("#invpn"))
        self.assertNotIn(str(self.root), flake_argument)


if __name__ == "__main__":
    unittest.main()
