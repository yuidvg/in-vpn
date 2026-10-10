"""Profiles reject unsupported inputs and keep imported credentials private."""
import base64
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from invpn.profiles import ProfileError, ProfileStore, parse_wireguard


PRIVATE_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
PUBLIC_KEY = base64.b64encode(bytes(range(32, 64))).decode("ascii")
PRESHARED_KEY = base64.b64encode(bytes(range(64, 96))).decode("ascii")


def wireguard(**changes):
    fields = {
        "private": PRIVATE_KEY,
        "address": "10.77.0.2/32",
        "dns": "10.77.0.53",
        "public": PUBLIC_KEY,
        "allowed": "0.0.0.0/0",
        "endpoint": "198.51.100.10:51820",
    }
    fields.update(changes)
    return (
        "[Interface]\n"
        f"PrivateKey = {fields['private']}\n"
        f"Address = {fields['address']}\n"
        f"DNS = {fields['dns']}\n"
        "\n[Peer]\n"
        f"PublicKey = {fields['public']}\n"
        f"AllowedIPs = {fields['allowed']}\n"
        f"Endpoint = {fields['endpoint']}\n"
    )


class WireGuardParsingTests(unittest.TestCase):
    def test_ipv4_and_dual_stack_profiles_are_accepted(self):
        for text in (
            wireguard(),
            wireguard(address="10.77.0.2/32, fd00:77::2/128", dns="10.77.0.53, fd00:77::53", allowed="0.0.0.0/0, ::/0", endpoint="[2001:db8::10]:51820"),
        ):
            with self.subTest(text=text):
                self.assertIsInstance(parse_wireguard(text), dict)

    def test_optional_transport_parameters_are_accepted(self):
        text = wireguard().replace("[Peer]", "MTU = 1280\n\n[Peer]")
        text += f"PresharedKey = {PRESHARED_KEY}\nPersistentKeepalive = 25\n"
        self.assertIsInstance(parse_wireguard(text), dict)

    def test_transport_defaults_and_peer_identity_are_preserved(self):
        profile = parse_wireguard(wireguard())
        self.assertEqual(profile["mtu"], 1280)
        self.assertEqual(profile["address"], ["10.77.0.2/32"])
        self.assertEqual(profile["dns"], ["10.77.0.53"])
        self.assertEqual(profile["peer"]["address"], "198.51.100.10")
        self.assertEqual(profile["peer"]["port"], 51820)
        self.assertEqual(profile["peer"]["public_key"], PUBLIC_KEY)
        self.assertEqual(profile["peer"]["allowed_ips"], ["0.0.0.0/0"])
        self.assertEqual(profile["peer"]["persistent_keepalive_interval"], 0)

    def test_partial_tunnel_is_rejected_in_this_version(self):
        for allowed in ("10.77.0.0/24", "::/0"):
            with self.subTest(allowed=allowed), self.assertRaises(ProfileError):
                parse_wireguard(wireguard(allowed=allowed))

    def test_rejects_wrong_key_lengths_and_invalid_base64(self):
        bad_keys = ("not-base64!", base64.b64encode(b"short").decode(), base64.b64encode(bytes(33)).decode())
        for key in bad_keys:
            for field in ("private", "public"):
                with self.subTest(field=field, key=key):
                    with self.assertRaises(ProfileError):
                        parse_wireguard(wireguard(**{field: key}))
        with self.assertRaises(ProfileError):
            parse_wireguard(wireguard() + "PresharedKey = invalid!\n")

    def test_rejects_missing_required_data(self):
        for line in ("PrivateKey", "Address", "DNS", "PublicKey", "AllowedIPs", "Endpoint"):
            text = "\n".join(value for value in wireguard().splitlines() if not value.startswith(line + " ="))
            with self.subTest(field=line), self.assertRaises(ProfileError):
                parse_wireguard(text)

    def test_rejects_unsupported_sections_and_multiple_peers(self):
        extra_peer = "\n[Peer]\nPublicKey = " + PUBLIC_KEY + "\nAllowedIPs = 192.0.2.0/24\nEndpoint = 198.51.100.11:51820\n"
        for text in (
            wireguard() + extra_peer,
            wireguard() + "\n[Other]\nValue = 1\n",
            wireguard().replace("[Interface]", "[Peer]"),
            wireguard().replace("[Peer]", "[Interface]"),
        ):
            with self.subTest(text=text), self.assertRaises(ProfileError):
                parse_wireguard(text)

    def test_rejects_fields_that_would_be_silently_ignored(self):
        for field in ("PostUp = touch /tmp/invpn-postup", "PostDown = true", "PreUp = true", "Table = auto", "ListenPort = 51820"):
            with self.subTest(field=field), self.assertRaises(ProfileError):
                parse_wireguard(wireguard().replace("[Peer]", field + "\n\n[Peer]"))
        with self.assertRaises(ProfileError):
            parse_wireguard(wireguard() + "TypoField = true\n")

    def test_rejects_names_and_invalid_ip_values(self):
        cases = (
            dict(address=""), dict(address="not-an-ip/24"), dict(address="10.77.0.2/33"), dict(address="10.77.0.2"),
            dict(allowed=""), dict(allowed="not-an-ip/24"), dict(allowed="::/129"),
            dict(dns=""), dict(dns="resolver.example.com"), dict(dns="10.77.0.53/32"),
            dict(endpoint="vpn.example.com:51820"), dict(endpoint="198.51.100.10:0"),
            dict(endpoint="198.51.100.10:65536"), dict(endpoint="[2001:db8::10]:wrong"),
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ProfileError):
                parse_wireguard(wireguard(**values))

    def test_rejects_out_of_range_transport_parameters(self):
        for mtu in ("575", "65536", "abc"):
            with self.subTest(mtu=mtu), self.assertRaises(ProfileError):
                parse_wireguard(wireguard().replace("[Peer]", f"MTU = {mtu}\n\n[Peer]"))
        for interval in ("-1", "65536", "abc"):
            with self.subTest(interval=interval), self.assertRaises(ProfileError):
                parse_wireguard(wireguard() + f"PersistentKeepalive = {interval}\n")


class ProfileStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.conf"
        self.source.write_text(wireguard())
        self.directory = self.root / "profiles"
        self.store = ProfileStore(self.directory)

    def test_import_preserves_source_and_secures_copy(self):
        original = self.source.read_bytes()
        imported = self.store.import_file("vpn1", self.source)
        self.assertEqual(imported, self.directory / "vpn1.conf")
        self.assertEqual(imported.read_bytes(), original)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(imported.stat().st_mode), 0o600)
        self.assertIsInstance(self.store.load("vpn1"), dict)

    def test_existing_profile_is_not_overwritten(self):
        imported = self.store.import_file("vpn1", self.source)
        original = imported.read_bytes()
        self.source.write_text(wireguard(endpoint="198.51.100.11:51820"))
        with self.assertRaises(ProfileError):
            self.store.import_file("vpn1", self.source)
        self.assertEqual(imported.read_bytes(), original)

    def test_rejects_unsafe_profile_names_for_import_and_load(self):
        for name in ("", ".", "..", "../outside", "/absolute", "x/y", "x y", "-vpn", "a" * 65, "vpn\nname"):
            with self.subTest(name=name):
                with self.assertRaises(ProfileError):
                    self.store.import_file(name, self.source)
                with self.assertRaises(ProfileError):
                    self.store.load(name)

    def test_lists_imported_profiles(self):
        self.store.import_file("vpn2", self.source)
        self.source.write_text(wireguard(private=PRESHARED_KEY))
        self.store.import_file("vpn1", self.source)
        (self.directory / "notes.txt").write_text("not a profile")
        self.assertEqual(self.store.names(), ["vpn1", "vpn2"])

    def test_duplicate_wireguard_identity_cannot_masquerade_as_another_vpn(self):
        self.store.import_file("vpn1", self.source)
        with self.assertRaises(ProfileError):
            self.store.import_file("vpn2", self.source)
        self.assertFalse((self.directory / "vpn2.conf").exists())

    def test_equivalent_noncanonical_base64_keys_are_one_wireguard_identity(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        variant = PRIVATE_KEY[:-2] + alphabet[alphabet.index(PRIVATE_KEY[-2]) + 1] + PRIVATE_KEY[-1]
        self.assertNotEqual(variant, PRIVATE_KEY)
        self.assertEqual(base64.b64decode(variant, validate=True), base64.b64decode(PRIVATE_KEY))
        parsed = parse_wireguard(wireguard(private=variant))
        self.assertEqual(parsed["private_key"], PRIVATE_KEY)
        self.store.import_file("vpn1", self.source)
        self.source.write_text(wireguard(private=variant))
        with self.assertRaises(ProfileError):
            self.store.import_file("alias", self.source)
        self.assertFalse((self.directory / "alias.conf").exists())

    def test_import_rejects_symlink_directory_and_binary_input(self):
        linked = self.root / "linked.conf"
        linked.symlink_to(self.source)
        binary = self.root / "binary.conf"
        binary.write_bytes(b"\xff\xfe\x00invalid")
        for source in (linked, self.root, binary):
            with self.subTest(source=source), self.assertRaises(ProfileError):
                self.store.import_file("invalid", source)
        self.assertFalse((self.directory / "invalid.conf").exists())

    def test_load_rejects_missing_insecure_and_symlink_profiles(self):
        with self.assertRaises(ProfileError):
            self.store.load("missing")
        imported = self.store.import_file("vpn1", self.source)
        imported.chmod(0o644)
        with self.assertRaises(ProfileError):
            self.store.load("vpn1")
        imported.unlink()
        imported.symlink_to(self.source)
        with self.assertRaises(ProfileError):
            self.store.load("vpn1")

    def test_read_only_private_profile_can_be_loaded(self):
        imported = self.store.import_file("vpn1", self.source)
        imported.chmod(0o400)
        self.assertIsInstance(self.store.load("vpn1"), dict)

    def test_load_rejects_profile_owned_by_another_user(self):
        self.store.import_file("vpn1", self.source)
        other_uid = os.getuid() + 1
        with patch("invpn.profiles.os.getuid", return_value=other_uid):
            with self.assertRaises(ProfileError):
                self.store.load("vpn1")

    def test_invalid_profile_is_not_imported(self):
        self.source.write_text(wireguard(private="bad"))
        with self.assertRaises(ProfileError):
            self.store.import_file("vpn1", self.source)
        self.assertFalse((self.directory / "vpn1.conf").exists())


if __name__ == "__main__":
    unittest.main()
