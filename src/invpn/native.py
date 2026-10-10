import json
import os
import re
import subprocess
from pathlib import Path

from .profiles import write_private

DEFAULT_HOST = Path("/Applications/InVPN.app/Contents/MacOS/InVPN")


class NativeError(RuntimeError):
    pass


class NativeController:
    def __init__(self, binary=DEFAULT_HOST):
        self.binary = Path(binary)
        self.registered_pid = None
        self.started = False

    def call(self, *arguments, timeout=25):
        if not self.binary.is_file():
            raise NativeError("InVPN.app is not installed; see docs/implementation.md")
        try:
            result = subprocess.run([str(self.binary), *map(str, arguments)], capture_output=True,
                                    text=True, timeout=timeout, close_fds=True)
            value = json.loads(result.stdout.strip().splitlines()[-1])
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
            raise NativeError(f"native {arguments[0]} failed or timed out; inspect InVPN.app / OS approval") from None
        if result.returncode or not value.get("success", False):
            reason = value.get("reason", "unknown")
            # Only the native protocol's fixed reason identifiers enter the user message.
            if not isinstance(reason, str) or not re.fullmatch(r"[a-z_]{1,100}", reason):
                reason = "unknown"
            raise NativeError(f"native {arguments[0]} rejected the operation: {reason} (check OS approval and state)")
        return value

    def start(self, host, port):
        state = self.call("status")
        if state.get("configured"):
            raise NativeError("InVPN already has a native configuration; remove it after checking active sessions")
        # Mark ownership before saving; even a timeout may have saved the setting.
        self.started = True
        value = self.call("start", host, port, timeout=180)
        if not value.get("ready"):
            raise NativeError("native Provider did not acknowledge readiness")

    def register(self, pid, bridge, session_dir):
        path = session_dir / "route.private.json"
        write_private(path, json.dumps({"pid": pid, "port": bridge.port, "secret": bridge.secret}))
        try:
            self.call("route", path)
            self.registered_pid = pid
        finally:
            path.unlink(missing_ok=True)

    def close(self):
        error = None
        if self.registered_pid is not None:
            try:
                self.call("unroute", self.registered_pid)
            except NativeError as caught:
                error = caught
            self.registered_pid = None
        if self.started:
            try:
                self.call("remove")
                error = None  # Removing the entire owned configuration also removes the route.
            except NativeError as caught:
                error = caught
            self.started = False
        if error:
            raise error
