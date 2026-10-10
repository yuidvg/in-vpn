"""Launch arguments verbatim, preserve the terminal, and close inherited extra FDs."""
import os
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path


class LaunchError(RuntimeError):
    pass


def reject_socket_stdio():
    for descriptor in (0, 1, 2):
        try:
            if stat.S_ISSOCK(os.fstat(descriptor).st_mode):
                raise LaunchError("socket-backed stdin/stdout/stderr is not supported; use a terminal, pipe or file")
        except OSError:
            continue


@contextmanager
def _ignore_ttou():
    original = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        yield
    finally:
        signal.signal(signal.SIGTTOU, original)


def _foreground(group):
    with _ignore_ttou():
        os.tcsetpgrp(0, group)


def _restore_foreground(original_group, child_group):
    if os.tcgetpgrp(0) in (os.getpgrp(), child_group):
        _foreground(original_group)


def _kill_group(process, number):
    try:
        os.killpg(process.pid, number)
    except ProcessLookupError:
        pass


def run_command(command, environment, before_release, backend_alive):
    """The child cannot exec until before_release has completed successfully."""
    reject_socket_stdio()
    terminal = os.isatty(0)
    original_group = os.tcgetpgrp(0) if terminal else None
    if terminal and original_group != os.getpgrp():
        raise LaunchError("start in-vpn as a foreground terminal job")
    read_fd, write_fd = os.pipe()
    process = None
    handlers = {}
    try:
        gate = Path(__file__).with_name("launch_gate.py")
        process = subprocess.Popen(
            [sys.executable, "-I", str(gate), str(read_fd), *command],
            env=environment, close_fds=True, pass_fds=(read_fd,), process_group=0,
        )
        os.close(read_fd)
        read_fd = -1
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            handlers[number] = signal.signal(number, lambda sig, frame: _kill_group(process, sig))
        before_release(process.pid)
        if terminal:
            _foreground(process.pid)
        os.write(write_fd, b"G")
        os.close(write_fd)
        write_fd = -1
        while True:
            if terminal and os.tcgetpgrp(0) == os.getpgrp():
                # `fg` can foreground an already-running `bg` wrapper too.
                _foreground(process.pid)
            pid, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
            if pid:
                if os.WIFSTOPPED(status):
                    if terminal:
                        _restore_foreground(original_group, process.pid)
                    # Return control to the outer shell. Its `fg` resumes us.
                    os.kill(os.getpid(), signal.SIGSTOP)
                    if terminal and os.tcgetpgrp(0) == os.getpgrp():
                        _foreground(process.pid)
                    _kill_group(process, signal.SIGCONT)
                    continue
                process.returncode = os.waitstatus_to_exitcode(status)
                return process.returncode if process.returncode >= 0 else 128 - process.returncode
            if not backend_alive():
                raise LaunchError("VPN backend exited; terminating the root command")
            time.sleep(0.03)
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                os.close(descriptor)
        if process is not None and process.returncode is None:
            _kill_group(process, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                _kill_group(process, signal.SIGKILL)
                process.wait(timeout=2)
        if terminal:
            _restore_foreground(original_group, process.pid if process is not None else os.getpgrp())
        for number, handler in handlers.items():
            signal.signal(number, handler)
