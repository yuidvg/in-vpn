"""Validate and store secrets without putting them in arguments or the repository."""
import base64
import configparser
import ipaddress
import os
import re
import secrets
import stat
from pathlib import Path


class ProfileError(ValueError):
    pass


def profile_name(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise ProfileError("profile name must contain 1–64 letters, digits, _, . or -")
    if name in {"capabilities", "doctor", "profiles", "status"}:
        raise ProfileError("this profile name is reserved for a management command")
    return name


def _key(value, field):
    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) != 32:
            raise ValueError()
    except (ValueError, TypeError):
        raise ProfileError(f"{field} must be a base64-encoded 32-byte key") from None
    # Equivalent base64 pad bits must not create different identity locks.
    return base64.b64encode(decoded).decode("ascii")


def _items(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def _number(value, field, low, high):
    try:
        number = int(value)
        if not low <= number <= high:
            raise ValueError()
    except ValueError:
        raise ProfileError(f"{field} must be an integer from {low} to {high}") from None
    return number


def parse_wireguard(text):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
    except configparser.Error:
        raise ProfileError("expected exactly one [Interface] and one [Peer]") from None
    if set(parser.sections()) != {"Interface", "Peer"} or parser.defaults():
        raise ProfileError("expected exactly one [Interface] and one [Peer]")
    interface, peer = parser["Interface"], parser["Peer"]
    fields = [(interface, {"privatekey", "address", "dns", "mtu"}),
              (peer, {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"})]
    for section, supported in fields:
        if set(section) - supported:
            raise ProfileError("unsupported WireGuard setting; hooks and host routing are not executed")
    try:
        address = _items(interface["Address"])
        dns = _items(interface["DNS"])
        allowed = _items(peer["AllowedIPs"])
        if not address or not dns or not allowed:
            raise ProfileError("Address, DNS and AllowedIPs must not be empty")
        for item in address:
            if "/" not in item:
                raise ProfileError("Address must include its network prefix")
            ipaddress.ip_interface(item)
        for item in dns:
            ipaddress.ip_address(item)
        networks = [ipaddress.ip_network(item, strict=False) for item in allowed]
        if ipaddress.ip_network("0.0.0.0/0") not in networks:
            raise ProfileError("this version requires IPv4 full-tunnel AllowedIPs (0.0.0.0/0)")
        endpoint = peer["Endpoint"]
        if endpoint.startswith("["):
            host, separator, raw_port = endpoint[1:].partition("]:")
            if not separator or ipaddress.ip_address(host).version != 6:
                raise ValueError()
        else:
            host, raw_port = endpoint.rsplit(":", 1)
            if ipaddress.ip_address(host).version != 4:
                raise ValueError()
        result = {
            "private_key": _key(interface["PrivateKey"], "PrivateKey"),
            "address": address, "dns": dns,
            "mtu": _number(interface.get("MTU", "1280"), "MTU", 576, 65535),
            "peer": {
                "address": host,
                "port": _number(raw_port, "Endpoint port", 1, 65535),
                "public_key": _key(peer["PublicKey"], "PublicKey"),
                "allowed_ips": allowed,
                "persistent_keepalive_interval": _number(peer.get("PersistentKeepalive", "0"), "PersistentKeepalive", 0, 65535),
            },
        }
        if "PresharedKey" in peer:
            result["peer"]["pre_shared_key"] = _key(peer["PresharedKey"], "PresharedKey")
        return result
    except KeyError:
        raise ProfileError("profile is missing a required WireGuard field") from None
    except (ValueError, IndexError) as error:
        if isinstance(error, ProfileError):
            raise
        raise ProfileError("invalid address or endpoint; use literal IP addresses (no bootstrap DNS)") from None


def private_directory(path):
    path = Path(path).expanduser().absolute()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ProfileError(f"directory must be owned by this user with mode 700: {path}")
    return path


def write_private(path, data):
    """Create, never overwrite, a private file, including when the name is a symlink."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _read_regular(path, private=False):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                raise ProfileError("profile must be a regular file no larger than 64 KiB")
            if private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)):
                raise ProfileError("stored profile must be owned by this user with mode 400 or 600")
            return stream.read()
    except (OSError, UnicodeError):
        raise ProfileError("cannot read profile; symlinks and non-text inputs are not supported") from None


class ProfileStore:
    def __init__(self, directory):
        self.directory = private_directory(directory)

    def names(self):
        return sorted(path.stem for path in self.directory.glob("*.conf")
                      if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", path.stem))

    def load(self, name):
        return parse_wireguard(_read_regular(self.directory / f"{profile_name(name)}.conf", private=True))

    def import_file(self, name, source):
        destination = self.directory / f"{profile_name(name)}.conf"
        text = _read_regular(source)
        profile = parse_wireguard(text)
        if destination.exists() or destination.is_symlink():
            raise ProfileError("profile already exists; choose another name")
        for existing in self.names():
            if secrets.compare_digest(self.load(existing)["private_key"], profile["private_key"]):
                raise ProfileError("this WireGuard identity already exists; simultaneous use can roam the peer")
        try:
            write_private(destination, text)
        except FileExistsError:
            raise ProfileError("profile already exists; choose another name") from None
        return destination
