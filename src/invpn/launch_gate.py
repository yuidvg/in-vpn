"""An exec barrier; this PID becomes the command only after registration is acknowledged."""
import os
import sys


def main():
    descriptor = int(sys.argv[1])
    try:
        allowed = os.read(descriptor, 1) == b"G"
    finally:
        os.close(descriptor)
    if not allowed:
        return 125
    try:
        os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
    except FileNotFoundError:
        print("in-vpn: command disappeared before exec", file=sys.stderr)
        return 127
    except OSError:
        print("in-vpn: command could not be executed", file=sys.stderr)
        return 126


if __name__ == "__main__":
    sys.exit(main())
