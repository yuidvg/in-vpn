"""Exercise the real exec barrier and OS process/FD behavior without a VPN."""
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from invpn.launcher import LaunchError, run_command


WRAPPER = """
import json, os, sys
from invpn.launcher import run_command
command = json.loads(sys.argv[1])
environment = dict(os.environ)
environment.update(json.loads(sys.argv[2]))
result = run_command(command, environment, lambda pid: None, lambda: True)
raise SystemExit(result)
"""


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.marker = self.root / "started"

    def environment(self):
        return dict(os.environ, PYTHONPATH=str(ROOT / "src"))

    def wrapper(self, command, extra_environment=None, **options):
        return subprocess.run(
            [sys.executable, "-c", WRAPPER, json.dumps(command), json.dumps(extra_environment or {})],
            cwd=self.root,
            env=self.environment(),
            capture_output=True,
            text=True,
            timeout=10,
            **options,
        )

    def test_registration_barrier_precedes_command_execution(self):
        registered = []

        def register(pid):
            registered.append(pid)
            self.assertFalse(self.marker.exists())
            os.kill(pid, 0)

        result = run_command(["/usr/bin/touch", str(self.marker)], self.environment(), register, lambda: True)
        self.assertEqual(result, 0)
        self.assertEqual(len(registered), 1)
        self.assertTrue(self.marker.exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(registered[0], 0)

    def test_registration_failure_never_releases_or_leaves_root_process(self):
        registered = []

        def refuse(pid):
            registered.append(pid)
            self.assertFalse(self.marker.exists())
            raise LaunchError("registration unavailable")

        with self.assertRaisesRegex(LaunchError, "registration unavailable"):
            run_command(["/usr/bin/touch", str(self.marker)], self.environment(), refuse, lambda: True)
        self.assertFalse(self.marker.exists())
        self.assertEqual(len(registered), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(registered[0], 0)

    def test_arguments_cwd_environment_and_pipes_are_preserved(self):
        arguments = ["two words", "$(touch should-not-exist)", "$HOME", "quote'and\"double", "", "日本語"]
        code = "import json,os,sys; print(json.dumps({'args':sys.argv[1:],'cwd':os.getcwd(),'env':os.environ['INVPN_TEST_VALUE'],'stdin':sys.stdin.read()},ensure_ascii=False)); print('child-stderr',file=sys.stderr); sys.exit(42)"
        result = self.wrapper([sys.executable, "-c", code, *arguments], {"INVPN_TEST_VALUE": "value with spaces"}, input="pipe input\n")
        self.assertEqual(result.returncode, 42, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["args"], arguments)
        self.assertEqual(Path(observed["cwd"]).resolve(), self.root.resolve())
        self.assertEqual(observed["env"], "value with spaces")
        self.assertEqual(observed["stdin"], "pipe input\n")
        self.assertEqual(result.stderr, "child-stderr\n")
        self.assertFalse((self.root / "should-not-exist").exists())

    def test_signal_exit_becomes_conventional_shell_exit_code(self):
        result = self.wrapper([sys.executable, "-c", "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"])
        self.assertEqual(result.returncode, 128 + signal.SIGTERM, result.stderr)

    def test_parent_termination_signal_reaches_running_root(self):
        pid_file = self.root / "root.pid"
        code = "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
        command = [sys.executable, "-c", code, str(pid_file)]
        process = subprocess.Popen(
            [sys.executable, "-c", WRAPPER, json.dumps(command), "{}"],
            cwd=self.root, env=self.environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        root_pid = None
        try:
            deadline = time.monotonic() + 5
            while root_pid is None and process.poll() is None and time.monotonic() < deadline:
                try:
                    root_pid = int(pid_file.read_text())
                except (FileNotFoundError, ValueError):
                    pass
                time.sleep(0.01)
            self.assertIsNotNone(root_pid, "root command did not reach its running state")
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 128 + signal.SIGTERM, stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(root_pid, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)
            if root_pid is not None:
                try:
                    os.killpg(root_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_missing_command_reports_127_after_gate_release(self):
        result = self.wrapper([str(self.root / "absent-command")])
        self.assertEqual(result.returncode, 127)
        self.assertIn("before exec", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_inherited_extra_file_descriptor_is_closed(self):
        source = self.root / "open-resource"
        source.write_text("an inherited resource")
        source_fd = os.open(source, os.O_RDONLY)
        inherited_fd = fcntl.fcntl(source_fd, fcntl.F_DUPFD, 64)
        os.set_inheritable(inherited_fd, True)
        os.close(source_fd)
        self.addCleanup(os.close, inherited_fd)
        output = self.root / "fd-result.json"
        code = """
import json,os,sys
try:
    os.fstat(int(sys.argv[1]))
    closed=False
except OSError:
    closed=True
with open(sys.argv[2],'w') as stream:
    json.dump({'closed':closed},stream)
"""
        result = run_command([sys.executable, "-c", code, str(inherited_fd), str(output)], self.environment(), lambda pid: None, lambda: True)
        self.assertEqual(result, 0)
        self.assertTrue(json.loads(output.read_text())["closed"])
        # Closing the child's copy must not close the caller's resource.
        os.fstat(inherited_fd)

    def test_socket_backed_stdin_is_rejected(self):
        source, peer = socket.socketpair()
        self.addCleanup(source.close)
        self.addCleanup(peer.close)
        code = """
from invpn.launcher import LaunchError,reject_socket_stdio
try:
    reject_socket_stdio()
except LaunchError as error:
    print(str(error))
    raise SystemExit(17)
raise SystemExit(0)
"""
        result = subprocess.run([sys.executable, "-c", code], stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment(), text=True, timeout=5)
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn("socket-backed", result.stdout)


if __name__ == "__main__":
    unittest.main()
