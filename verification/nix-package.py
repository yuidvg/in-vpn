#!/usr/bin/env python3
"""Check an installed Nix CLI on macOS without a real VPN or external requests.

Run outside the Nix build sandbox. The synthetic backend accepts a localhost
authentication handshake only; this does not test WireGuard reachability,
Network Extension activation, DNS isolation or direct-traffic containment.
"""
import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


class VerificationFailure(RuntimeError):
    pass


def private_write(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def absent(pid):
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True


def invoke(command, directory, environment):
    process = subprocess.Popen(command, cwd=directory, env=environment,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=35)
    except BaseException:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=3)
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def verify(package, checks):
    def check(name, condition, detail):
        checks.append({"case": name, "passed": bool(condition)})
        if not condition:
            raise VerificationFailure(detail)

    check("macos_host", sys.platform == "darwin", "run this check on macOS outside the Nix sandbox")
    check("package_path", package.is_absolute() and package.is_dir(), "--package must be an absolute installed package directory")
    package = package.resolve()
    binaries = [package / "bin" / name for name in ("in-vpn", "invpn")]
    check("both_aliases_installed", all(path.is_file() and os.access(path, os.X_OK) for path in binaries),
          "both installed CLI aliases must be executable")
    gates = list(package.glob("lib/python*/site-packages/invpn/launch_gate.py"))
    check("installed_launch_gate", len(gates) == 1 and gates[0].is_file(), "installed launch_gate.py is missing or ambiguous")

    with tempfile.TemporaryDirectory(prefix="invpn-nix-package-") as temporary:
        workspace = Path(temporary)
        workspace.chmod(0o700)
        foreign = workspace / "foreign-cwd"
        user_bin = workspace / "user-bin"
        shadow = workspace / "python-shadow"
        profiles = workspace / "profiles"
        state_dir = workspace / "state"
        for directory in (foreign, user_bin, shadow, profiles):
            directory.mkdir(mode=0o700)
        (shadow / "invpn").mkdir(mode=0o700)
        private_write(shadow / "invpn/__init__.py", 'raise RuntimeError("caller PYTHONPATH must not load invpn")\n')
        private_write(foreign / "fixture.txt", "local fixture 日本語\n")
        observation = workspace / "command-observation.json"
        helper = workspace / "command-probe.py"
        private_write(helper, '''import json, os, sys
from pathlib import Path
value = {"environment": {name: os.environ.get(name) for name in ("PATH", "PYTHONPATH", "PYTHONNOUSERSITE")},
         "cwd": os.getcwd(), "fixture": Path("fixture.txt").read_text(), "argv": sys.argv[1:]}
Path(os.environ["INVPN_PACKAGE_PROBE_OUTPUT"]).write_text(json.dumps(value, ensure_ascii=False))
sys.exit(17)
''')
        probe = user_bin / "invpn-package-command"
        private_write(probe, "#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I " + shlex.quote(str(helper)) + ' "$@"\n')
        probe.chmod(0o700)
        # The caller has no sing-box on PATH. Python import poisoning and its
        # environment variables must be ignored by the CLI and kept for its child.
        environment = dict(os.environ, PATH=str(user_bin), PYTHONPATH=str(shadow),
                           PYTHONNOUSERSITE="invpn-package-preserve",
                           INVPN_PACKAGE_PROBE_OUTPUT=str(observation))
        environment.pop("INVPN_SING_BOX", None)
        environment.pop("INVPN_SESSION", None)
        versions = []
        for binary in binaries:
            result = invoke([str(binary), "--version"], foreign, environment)
            versions.append(result.stdout.strip())
            check("version_" + binary.name, result.returncode == 0 and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", versions[-1]) is not None,
                  "installed alias --version failed")
        check("aliases_same_version", versions[0] == versions[1], "installed aliases report different versions")
        cli = [str(binaries[0]), "--config-dir", str(profiles), "--state-dir", str(state_dir)]
        result = invoke([*cli, "--json", "capabilities"], foreign, environment)
        check("capabilities_command", result.returncode == 0, "installed capabilities command failed")
        capabilities = json.loads(result.stdout)
        check("capabilities_honest_partial", capabilities.get("version") == versions[0]
              and capabilities.get("status") == "partial" and capabilities.get("default_mode") == "isolated"
              and capabilities.get("modes", {}).get("isolated", {}).get("available") is False,
              "capabilities do not state partial implementation with unavailable default isolation")
        marker = foreign / "must-not-execute"
        result = invoke([*cli, "vpn1", "/usr/bin/touch", str(marker)], foreign, environment)
        check("default_refuses_before_execution", result.returncode != 0 and not marker.exists()
              and "isolated mode is unavailable" in result.stderr,
              "default mode did not refuse before the supplied command")
        result = invoke([*cli, "--json", "doctor"], foreign, environment)
        check("doctor_command", result.returncode == 0, "doctor failed with minimal caller PATH")
        doctor = json.loads(result.stdout)
        backend = doctor.get("sing_box")
        check("pinned_backend_without_path", isinstance(backend, str) and Path(backend).is_absolute()
              and backend.startswith("/nix/store/") and Path(backend).is_file()
              and re.match(r"^sing-box version 1\.14\.\d+(?:\s|$)", doctor.get("sing_box_version") or "") is not None,
              "doctor did not discover the pinned absolute sing-box 1.14.x")

        # These public fixture bytes are not the user's keys. Keepalive=0 and a
        # file-only child ensure no VPN destination or external API is requested.
        private_key = base64.b64encode(bytes(range(32))).decode("ascii")
        public_key = base64.b64encode(bytes(range(32, 64))).decode("ascii")
        private_write(profiles / "vpn1.conf", "[Interface]\nPrivateKey = " + private_key
                      + "\nAddress = 10.77.0.2/32\nDNS = 10.77.0.53\n\n[Peer]\nPublicKey = "
                      + public_key + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.10:51820\nPersistentKeepalive = 0\n")
        arguments = ["space argument", "日本語", "--literal=$x;*", "line1\nline2"]
        result = invoke([*cli, "--mode", "proxy", "vpn1", probe.name, *arguments], foreign, environment)
        # Always inspect final resources even when the invocation failed.
        states = list(state_dir.glob("sessions/*/state.json"))
        check("single_session_state", len(states) == 1, "expected exactly one session state")
        state = json.loads(states[0].read_text())
        check("private_backend_config_removed", not (states[0].parent / "backend.private.json").exists(),
              "generated private backend configuration remains after CLI exit")
        pid = state.get("backend_pid")
        check("owned_backend_exited", isinstance(pid, int) and pid > 0 and absent(pid),
              "the owned backend remains present or its PID was not recorded")
        check("proxy_child_exit17", result.returncode == 17, "proxy child did not return exit code 17")
        check("session_finished_exit17", state.get("state") == "finished" and state.get("exit_code") == 17,
              "session state did not record finished/17")
        check("child_observation_written", observation.is_file(), "the user-PATH command did not write its observation")
        child = json.loads(observation.read_text())
        check("child_environment_preserved", child.get("environment") == {name: environment[name] for name in ("PATH", "PYTHONPATH", "PYTHONNOUSERSITE")},
              "packaging changed the child's PATH or Python environment variables")
        child_cwd = child.get("cwd")
        same_directory = isinstance(child_cwd, str) and os.path.samefile(child_cwd, foreign)
        check("cwd_and_relative_file_preserved", same_directory and child.get("fixture") == "local fixture 日本語\n",
              "the child did not preserve cwd or access its relative file")
        check("arguments_preserved", child.get("argv") == arguments, "the child arguments were changed")
        check("private_state_and_log", states[0].stat().st_mode & 0o077 == 0
              and (states[0].parent / "backend.private.log").is_file()
              and (states[0].parent / "backend.private.log").stat().st_mode & 0o077 == 0,
              "retained state or backend log is not private")
        return {"version": versions[0], "backend": backend, "backend_version": doctor["sing_box_version"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True, help="absolute installed Nix output directory")
    parser.add_argument("--output", type=Path, help="new private JSON file; parent must have permissions 0700")
    args = parser.parse_args()
    os.umask(0o077)
    checks = []
    summary = {"scope": "installed CLI packaging; no VPN reachability or isolation claims",
               "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "package": str(args.package), "checks": checks}
    try:
        summary.update(verify(args.package, checks))
        summary["passed"] = True
    except Exception as error:
        summary["passed"] = False
        summary["error"] = str(error) if isinstance(error, VerificationFailure) else type(error).__name__
    summary["total_checks"] = len(checks)
    summary["passed_checks"] = sum(check["passed"] for check in checks)
    output = json.dumps(summary, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        path = args.output.expanduser().absolute()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        information = path.parent.stat()
        if path.parent.is_symlink() or information.st_uid != os.getuid() or information.st_mode & 0o077:
            parser.error("--output parent must be a private directory owned by the current user")
        try:
            private_write(path, output)
        except FileExistsError:
            parser.error("--output must name a new file")
    print(output, end="")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
