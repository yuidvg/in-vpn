"""Defer ordinary termination signals until an owned cleanup finishes."""
import signal
import threading
from contextlib import contextmanager


@contextmanager
def finish_cleanup():
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    pending = []
    original = {number: signal.signal(number, lambda sig, frame: pending.append(sig))
                for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)}
    try:
        yield
    finally:
        for number, handler in original.items():
            signal.signal(number, handler)
        if pending:
            number = pending[0]
            handler = original[number]
            if callable(handler):
                handler(number, None)
            elif handler == signal.SIG_DFL:
                signal.raise_signal(number)
