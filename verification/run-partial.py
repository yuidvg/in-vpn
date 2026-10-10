#!/usr/bin/env python3
"""Observe the partial CLI through its public entry point; raw data stays local."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pty
import secrets
import select
import signal
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--profile", default="vpn1")
    parser.add_argument("--transparent", action="store_true", help="Requires installed/approved InVPN.app")
    args = parser.parse_args()
    os.umask(0o077)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = ROOT / ".local/runs/acceptance" / (stamp + "-partial-" + secrets.token_hex(3))
    run.mkdir(parents=True, mode=0o700)
    cli = [str(ROOT / "bin/in-vpn"), "--config-dir", str(args.config_dir.resolve()), "--state-dir", str(run / "sessions")]
    results = []
    raw = []

    def invoke(label, command, **options):
        value = subprocess.run(command, capture_output=True, text=True, timeout=45, cwd=ROOT, **options)
        raw.append({"case": label, "returncode": value.returncode, "stdout": value.stdout, "stderr": value.stderr})
        return value

    curl = ["/usr/bin/curl", "--disable", "--fail", "--silent", "--show-error", "--max-time", "25", "-4", "--http1.1"]
    try:
        baseline = invoke("normal_https", [*curl, "--proxy", "", "--noproxy", "*", "https://api.ipify.org"])
        normal = str(ipaddress.ip_address(baseline.stdout.strip()))
        tunnel_addresses = []
        for number in range(3):
            value = invoke(f"proxy_https_domain_{number}", [*cli, "--mode", "proxy", args.profile, *curl, "https://api.ipify.org"])
            try:
                address = str(ipaddress.ip_address(value.stdout.strip()))
                tunnel_addresses.append(address)
                results.append({"case": f"proxy_https_domain_{number}", "http_success": value.returncode == 0, "exit_differs_from_normal": address != normal})
            except ValueError:
                results.append({"case": f"proxy_https_domain_{number}", "http_success": False, "returncode": value.returncode})
        marker = "space 日本語 * $ literal\nnext line"
        environment = dict(os.environ, INVPN_CHECK="preserved")
        script = 'test "$PWD" = "$1" && test "$INVPN_CHECK" = preserved && print -rn -- "$2" > "$3" && cat "$3"; exit 17'
        value = invoke("workspace", [*cli, "--mode", "proxy", args.profile, "/bin/zsh", "-f", "-c", script, "probe", str(ROOT), marker, str(run / "workspace.txt")], env=environment)
        results.append({"case": "workspace", "passed": value.returncode == 17 and value.stdout == marker and (run / "workspace.txt").read_text() == marker})
        value = invoke("command_signal", [*cli, "--mode", "proxy", args.profile, "/bin/zsh", "-f", "-c", "kill -TERM $$"])
        results.append({"case": "command_signal", "passed": value.returncode == 143})
        refused = run / "must-not-execute"
        value = invoke("isolated_refusal", [*cli, args.profile, "/usr/bin/touch", str(refused)])
        results.append({"case": "isolated_refusal", "passed": value.returncode != 0 and not refused.exists()})

        # This bootstrap intentionally uses the normal resolver, independent of
        # tests of proxy-supplied names. It is not isolated system DNS.
        address = socket.getaddrinfo("api.ipify.org", 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        direct_socket = '''import socket,ssl,sys
c=socket.create_connection((sys.argv[1],443),timeout=20)
with ssl.create_default_context().wrap_socket(c,server_hostname="api.ipify.org") as s:
 s.sendall(b"GET / HTTP/1.0\\r\\nHost: api.ipify.org\\r\\nConnection: close\\r\\n\\r\\n")
 data=b""
 while True:
  part=s.recv(4096)
  if not part: break
  data+=part
 print(data.split(b"\\r\\n\\r\\n",1)[1].decode().strip())
'''
        value = invoke("proxy_ignored_socket", [*cli, "--mode", "proxy", args.profile, "python3", "-c", direct_socket, address])
        results.append({"case": "proxy_ignored_socket", "ordinary_socket_uses_normal_exit": value.returncode == 0 and value.stdout.strip() == normal})

        # Exercise shell job control through a genuine controlling terminal.
        (run / "empty-zdotdir").mkdir()
        pid, terminal = pty.fork()
        if pid == 0:
            environment = dict(os.environ, SHELL="/bin/zsh", ZDOTDIR=str(run / "empty-zdotdir"))
            os.execvpe(cli[0], [*cli, "--mode", "proxy", args.profile, "shell"], environment)
        output = bytearray()
        try:
            deadline = time.monotonic() + 12
            # Wait for the terminal shell, then exercise background/foreground
            # jobs and terminal state; no saved user shell config is loaded.
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.2)[0]:
                    output.extend(os.read(terminal, 65536))
                if b"% " in output or b"# " in output:
                    break
            os.write(terminal, b"[[ -t 0 && -t 1 ]] && print INVPN_TTY_OK\nsleep 0.2 &\nwait\nprint INVPN_JOBS_OK\nexit 17\n")
            status = None
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.2)[0]:
                    try:
                        output.extend(os.read(terminal, 65536))
                    except OSError:
                        pass
                waited, value = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = os.waitstatus_to_exitcode(value)
                    break
            results.append({"case": "interactive_shell_pty", "passed": status == 17 and b"INVPN_TTY_OK\r\n" in output and b"INVPN_JOBS_OK\r\n" in output})
            raw.append({"case": "interactive_shell_pty", "returncode": status, "terminal": output.decode(errors="replace")})
            if status is None:
                os.kill(pid, signal.SIGTERM)
                os.waitpid(pid, 0)
        finally:
            os.close(terminal)

        if args.transparent:
            value = invoke("transparent_root_socket", [*cli, "--mode", "transparent", "--experimental", "--destination", f"{address}:443", args.profile, "python3", "-c", direct_socket, address])
            expected = tunnel_addresses[0] if tunnel_addresses else None
            results.append({"case": "transparent_root_socket", "http_success": value.returncode == 0, "matches_proxy_exit": expected is not None and value.stdout.strip() == expected, "exit_differs_from_normal": value.returncode == 0 and value.stdout.strip() != normal})
    except Exception as error:
        results.append({"case": "harness_error", "type": type(error).__name__})
    finally:
        (run / "observations.private.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2))
        hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for base in [ROOT / "src", ROOT / "macos"] for path in base.rglob("*")
                  if path.is_file() and path.suffix in {".py", ".swift", ".c", ".h", ".plist", ".entitlements"}}
        summary = {"scope": "partial CLI; not V00–V25 product acceptance", "results": results,
                   "source_sha256": hashes, "raw_evidence": str(run / "observations.private.json")}
        (run / "summary.json").write_text(json.dumps(summary, indent=2))
        print(json.dumps({"run": str(run), "results": results}, indent=2))


if __name__ == "__main__":
    main()
