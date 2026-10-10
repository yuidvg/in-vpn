import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import signal
import secrets
import shutil
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from . import __version__
from .capabilities import capabilities, warning
from .launcher import LaunchError, reject_socket_stdio, run_command
from .lifecycle import finish_cleanup
from .native import DEFAULT_HOST, NativeController, NativeError
from .profiles import ProfileError, ProfileStore, _key, private_directory, profile_name, write_private

HOME_DIRECTORY = Path.home() / "Library/Application Support/InVPN"
LOCK_DIRECTORY = Path(pwd.getpwuid(os.getuid()).pw_dir) / "Library/Application Support/InVPN/locks"


class SessionCancelled(Exception):
    def __init__(self, number):
        self.number = number


class CleanupStack(ExitStack):
    def __exit__(self, error_type, error, traceback):
        with finish_cleanup():
            return super().__exit__(error_type, error, traceback)


@contextmanager
def _cleanup_signals():
    """A normal TERM/HUP during preparation must unwind owned resources."""
    cancelling = False

    def cancel(number, frame):
        nonlocal cancelling
        if not cancelling:
            cancelling = True
            raise SessionCancelled(number)

    original = {number: signal.signal(number, cancel)
                for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)}
    try:
        yield
    finally:
        for number, handler in original.items():
            signal.signal(number, handler)


def parser():
    result = argparse.ArgumentParser(
        prog="in-vpn", description="Partial VPN execution for macOS. Default isolated mode is unavailable.",
        epilog="Examples: in-vpn --mode proxy vpn1 curl https://example.com; in-vpn --mode proxy vpn1 shell",
    )
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--config-dir", type=Path, default=Path(os.environ.get("INVPN_CONFIG_DIR", HOME_DIRECTORY / "profiles")))
    result.add_argument("--state-dir", type=Path)
    result.add_argument("--mode", choices=("isolated", "proxy", "transparent"), default="isolated")
    result.add_argument("--experimental", action="store_true")
    result.add_argument("--destination", help="transparent mode: one IPv4:port (not port 53)")
    result.add_argument("--json", action="store_true", help="JSON for capabilities, doctor, profiles list or status")
    result.add_argument("target", nargs="?", help="profile name, or capabilities | doctor | profiles | status")
    result.add_argument("command", nargs=argparse.REMAINDER)
    return result


def _output(value, as_json=False):
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2))
    elif isinstance(value, list):
        print("\n".join(value))
    else:
        for name, item in value.items():
            print(f"{name}: {json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list, bool)) else item}")


@contextmanager
def _lock(path):
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LaunchError("another session holds this profile or transparent-mode lock") from None
        yield
    finally:
        os.close(descriptor)


def _same_mirror_identity(profile):
    path = Path.home() / ".config/mirror/vpn.json"
    if path.is_file():
        try:
            config = json.loads(path.read_text())
        except (ValueError, OSError):
            raise ProfileError("cannot check the existing mirror WireGuard identity") from None
        if any(_key(item["private_key"], "mirror private key") == profile["private_key"]
               for item in config.get("endpoints", []) + config.get("outbounds", [])
               if item.get("private_key")):
            raise ProfileError("this profile shares the mirror WireGuard identity; use a dedicated identity")


def _destination(value):
    try:
        host, port = value.rsplit(":", 1)
        address = ipaddress.ip_address(host)
        number = int(port)
        if address.version != 4 or not 0 < number <= 65535 or number == 53:
            raise ValueError()
        if address.is_multicast or address.is_unspecified:
            raise ValueError()
        return str(address), number
    except (ValueError, AttributeError):
        raise LaunchError("--destination must be one unicast IPv4:port, with port 1–65535 other than 53") from None


def _command(arguments, mode):
    raw = list(arguments)
    literal = bool(raw and raw[0] == "--")
    if literal:
        raw.pop(0)
    if not raw:
        raise LaunchError("provide a command or shell")
    if raw[0] == "shell" and not literal:
        if len(raw) != 1:
            raise LaunchError("shell takes no arguments; invoke the shell executable for custom options")
        if mode == "transparent":
            raise LaunchError("transparent shell is unavailable: child processes are not selected")
        shell = os.environ.get("SHELL") or pwd.getpwuid(os.getuid()).pw_shell
        raw = [shell, "-i"]
    resolved = shutil.which(raw[0])
    if resolved is None or not os.path.isfile(resolved):
        raise FileNotFoundError("command not found")
    return [os.path.abspath(resolved), *raw[1:]]


def _backend_binary():
    """Allow packaging to pin the backend without changing the user's PATH."""
    configured = os.environ.get("INVPN_SING_BOX")
    if configured is not None:
        path = Path(configured)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise LaunchError("INVPN_SING_BOX must name an absolute executable file")
        return str(path)
    return shutil.which("sing-box")


def _doctor():
    binary = _backend_binary()
    version = None
    if binary:
        result = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=5)
        version = result.stdout.splitlines()[0] if result.returncode == 0 and result.stdout else "unavailable"
    native_enabled = None
    if sys.platform == "darwin":
        result = subprocess.run(["/usr/bin/systemextensionsctl", "list"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            native_enabled = any("\tjp.diverge.invpn.proxy " in line and "[activated enabled]" in line
                                 for line in result.stdout.splitlines())
    return {"platform": sys.platform, "python": sys.version.split()[0], "sing_box": binary,
            "sing_box_version": version, "native_app_installed": DEFAULT_HOST.is_file(),
            "native_extension_enabled": native_enabled,
            "proxy_dependencies_present": sys.platform == "darwin" and binary is not None,
            "fully_isolated_execution_available": False,
            "note": "dependency checks do not establish VPN reachability, OS approval or isolation; run capabilities"}


def _status(state_dir):
    sessions = []
    if state_dir.is_dir():
        for path in state_dir.glob("sessions/*/state.json"):
            try:
                value = json.loads(path.read_text())
                if value.get("state") == "running":
                    try:
                        os.kill(value["cli_pid"], 0)
                        value["cli_pid_present"] = True
                    except ProcessLookupError:
                        value["cli_pid_present"] = False
                        value["state"] = "interrupted"
                sessions.append(value)
            except (OSError, ValueError, KeyError):
                continue
    return {"sessions": sessions, "isolation_guaranteed": False}


def _execute(args, config_dir, state_dir):
    if args.mode == "isolated":
        raise LaunchError("isolated mode is unavailable: descendant tracking, DNS isolation and crash containment are unresolved. Choose --mode proxy, or --mode transparent --experimental --destination IPv4:port after reading capabilities.")
    if args.mode == "transparent" and not args.experimental:
        raise LaunchError("transparent mode requires --experimental because direct traffic can leak")
    destination = _destination(args.destination) if args.mode == "transparent" else None
    if args.mode == "proxy" and args.destination:
        raise LaunchError("--destination applies only to transparent mode")
    if os.environ.get("INVPN_SESSION"):
        raise LaunchError("nested in-vpn sessions are not supported")
    if sys.platform != "darwin":
        raise LaunchError("this implementation supports macOS only")
    command = _command(args.command, args.mode)
    reject_socket_stdio()
    store = ProfileStore(config_dir)
    profile = store.load(args.target)
    _same_mirror_identity(profile)
    binary = _backend_binary()
    if binary is None:
        raise LaunchError("sing-box is not installed")
    state_dir = private_directory(state_dir)
    lock_directory = private_directory(LOCK_DIRECTORY)
    sessions = private_directory(state_dir / "sessions")
    session_id = secrets.token_hex(12)
    session_dir = private_directory(sessions / session_id)
    state = {"id": session_id, "profile": args.target, "mode": args.mode,
             "cli_pid": os.getpid(), "started_at": time.time(), "state": "preparing"}
    state_path = session_dir / "state.json"
    write_private(state_path, json.dumps(state))
    print(warning(args.mode, args.destination), file=sys.stderr)
    from .transport import Backend
    from .bridge import Bridge
    result = 125
    try:
        with CleanupStack() as stack:
            identity = hashlib.sha256(profile["private_key"].encode()).hexdigest()
            stack.enter_context(_lock(lock_directory / f"wireguard-{identity}.lock"))
            if destination:
                stack.enter_context(_lock(lock_directory / "transparent.lock"))
            backend = stack.enter_context(Backend(profile, session_dir, binary=binary))
            environment = dict(os.environ, INVPN_SESSION=session_id, INVPN_PROFILE=args.target, INVPN_MODE=args.mode)
            native = None
            bridge = None
            if destination:
                bridge = stack.enter_context(Bridge(backend))
                native = NativeController()
                stack.callback(native.close)
                native.start(*destination)
            else:
                environment.update(backend.proxy_environment())

            def release(pid):
                if native:
                    native.register(pid, bridge, session_dir)
                state.update(state="running", root_pid=pid, backend_pid=backend.process.pid)
                state_path.write_text(json.dumps(state))

            result = run_command(command, environment, release, lambda: backend.process.poll() is None)
            if bridge:
                write_private(session_dir / "transport-summary.json", json.dumps({"events": bridge.events}))
            if native:
                value = native.call("events")
                own_events = [event for event in value.get("events", []) if event.get("pid") == state["root_pid"]]
                write_private(session_dir / "native-summary.json", json.dumps({"root_events": own_events}))
        state["state"] = "finished"
    except SessionCancelled as error:
        result = 128 + error.number
        state["state"] = "cancelled"
        raise
    except BaseException:
        state["state"] = "failed"
        raise
    finally:
        state.update(ended_at=time.time(), exit_code=result)
        state_path.write_text(json.dumps(state))
    return result


def main(arguments=None):
    args = parser().parse_args(arguments)
    # Management JSON may be written before or after its command name.
    as_json = args.json or (args.target in {"capabilities", "doctor", "status", "profiles"} and "--json" in args.command)
    config_dir = args.config_dir.expanduser().absolute()
    state_dir = (args.state_dir or config_dir.parent / "run").expanduser().absolute()
    try:
        if args.target is None:
            parser().print_help()
            return 0
        if args.target == "capabilities":
            _output(capabilities(), as_json)
            return 0
        if args.target == "doctor":
            _output(_doctor(), as_json)
            return 0
        if args.target == "status":
            _output(_status(state_dir), as_json)
            return 0
        if args.target == "profiles":
            commands = [item for item in args.command if item != "--json"]
            store = ProfileStore(config_dir)
            if commands in ([], ["list"]):
                _output(store.names(), as_json)
                return 0
            if len(commands) == 3 and commands[0] == "import":
                path = store.import_file(commands[1], Path(commands[2]).expanduser())
                _output({"imported": commands[1], "path": str(path)}, as_json)
                return 0
            raise LaunchError("usage: profiles list | profiles import NAME /path/to/WireGuard.conf")
        with _cleanup_signals():
            return _execute(args, config_dir, state_dir)
    except SessionCancelled as error:
        print("in-vpn: cancelled; owned resources were closed", file=sys.stderr)
        return 128 + error.number
    except FileNotFoundError:
        print("in-vpn: command not found", file=sys.stderr)
        return 127
    except (ProfileError, LaunchError, NativeError) as error:
        print(f"in-vpn: {error}", file=sys.stderr)
        return 78
    except (OSError, RuntimeError, subprocess.SubprocessError):
        print("in-vpn: operation failed; see the private session log and doctor", file=sys.stderr)
        return 69


if __name__ == "__main__":
    sys.exit(main())
