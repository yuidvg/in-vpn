#!/usr/bin/env python3
"""Exercise two real CLI proxy sessions through independent local WireGuard peers."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from invpn.profiles import ProfileStore, write_private


class Receiver:
    def __init__(self, label):
        self.label, self.requests, self.workers = label, [], []
        self.barrier = None
        self.closed = threading.Event()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.server.settimeout(0.1)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.closed.is_set():
            try:
                stream, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.serve, args=(stream,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, stream):
        with stream:
            try:
                stream.settimeout(5)
                request = bytearray()
                while b"\r\n\r\n" not in request and len(request) < 8192:
                    part = stream.recv(4096)
                    if not part:
                        return
                    request.extend(part)
                line = request.split(b"\r\n", 1)[0].decode("ascii")
                path = line.split(" ")[1]
                observation = {"receiver": self.label, "path": path, "arrived_at": time.time(), "paired_overlap": False}
                self.requests.append(observation)
                self.barrier.wait(timeout=5)
                observation["paired_overlap"] = True
                body = self.label.encode()
                stream.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            except (OSError, ValueError, IndexError, threading.BrokenBarrierError):
                return

    def close(self):
        self.closed.set()
        self.server.close()
        if self.barrier:
            self.barrier.abort()
        self.thread.join(timeout=1)
        for worker in self.workers:
            worker.join(timeout=1)


def absent(pid):
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def main():
    os.umask(0o077)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = ROOT / ".local/product/checks" / (stamp + "-parallel-local-" + secrets.token_hex(3))
    run.mkdir(parents=True, mode=0o700)
    config = run / "profiles"
    config.mkdir(mode=0o700)
    receivers, servers, logs, commands, results, raw = [], [], [], [], [], []
    error = None
    try:
        for label in ("vpn1", "vpn2"):
            receiver = Receiver(label)
            receivers.append(receiver)
            pairs = []
            for _ in range(2):
                output = subprocess.check_output(["sing-box", "generate", "wg-keypair"], text=True, timeout=5)
                pairs.append(dict(line.split(": ", 1) for line in output.strip().splitlines()))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1", 0))
                peer_port = reserved.getsockname()[1]
            settings = {
                "log": {"level": "warn"},
                "endpoints": [{"type": "wireguard", "tag": "local-peer", "system": False, "listen_port": peer_port,
                               "address": ["10.77.0.1/24"], "private_key": pairs[0]["PrivateKey"],
                               "peers": [{"public_key": pairs[1]["PublicKey"], "allowed_ips": ["10.77.0.2/32"]}]}],
                "outbounds": [{"type": "direct", "tag": "local-receiver"}],
                "route": {"rules": [{"network": "tcp", "action": "route", "outbound": "local-receiver",
                                      "override_address": "127.0.0.1", "override_port": receiver.port}], "final": "local-receiver"},
            }
            server_path = run / (label + "-server.private.json")
            write_private(server_path, json.dumps(settings))
            descriptor = os.open(run / (label + "-server.private.log"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            log = os.fdopen(descriptor, "wb")
            logs.append(log)
            checked = subprocess.run(["sing-box", "check", "-c", str(server_path)], stdout=log, stderr=log, timeout=5)
            if checked.returncode:
                raise RuntimeError("synthetic_peer_configuration_rejected")
            servers.append(subprocess.Popen(["sing-box", "run", "-c", str(server_path)], stdin=subprocess.DEVNULL, stdout=log, stderr=log))
            text = ("[Interface]\nPrivateKey = " + pairs[1]["PrivateKey"] + "\nAddress = 10.77.0.2/32\nDNS = 10.77.0.53\nMTU = 1280\n\n[Peer]\nPublicKey = "
                    + pairs[0]["PublicKey"] + f"\nEndpoint = 127.0.0.1:{peer_port}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 0\n")
            write_private(config / (label + ".conf"), text)
        store = ProfileStore(config)
        if store.load("vpn1")["private_key"] == store.load("vpn2")["private_key"]:
            raise RuntimeError("synthetic_identities_are_not_independent")
        time.sleep(0.1)
        if any(server.poll() is not None for server in servers):
            raise RuntimeError("synthetic_peer_exited")
        for pair in range(3):
            barrier = threading.Barrier(2)
            for receiver in receivers:
                receiver.barrier = barrier
            current = []
            for index, label in enumerate(("vpn1", "vpn2")):
                path = f"/pair-{pair}/{label}/{secrets.token_hex(8)}"
                arguments = [str(ROOT / "bin/in-vpn"), "--config-dir", str(config), "--state-dir", str(run / ("state-a" if index == 0 else "state-b")),
                             "--mode", "proxy", label, "/usr/bin/curl", "--disable", "--fail", "--silent", "--show-error", "--max-time", "10", "http://10.77.0.99:18080" + path]
                process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT, start_new_session=True)
                commands.append(process)
                current.append((label, path, process))
            for label, path, process in current:
                output, diagnostics = process.communicate(timeout=20)
                raw.append({"pair": pair, "profile": label, "stdout": output.decode(errors="replace"), "stderr": diagnostics.decode(errors="replace"), "exit_code": process.returncode})
                own = [request for request in receivers[0 if label == "vpn1" else 1].requests if request["path"] == path]
                other = [request for request in receivers[1 if label == "vpn1" else 0].requests if request["path"] == path]
                results.append({"pair": pair, "profile": label, "cli_exit": process.returncode, "body_matches_profile": output.decode() == label,
                                "path": path, "correct_receiver_requests": len(own), "other_receiver_requests": len(other),
                                "paired_overlap": len(own) == 1 and own[0]["paired_overlap"]})
    except Exception as caught:
        error = type(caught).__name__
    finally:
        for command in commands:
            stop(command)
        for server in servers:
            stop(server)
        for receiver in receivers:
            receiver.close()
        for log in logs:
            log.close()
        states = [json.loads(path.read_text()) for path in run.glob("state-*/sessions/*/state.json")]
        owned_pids = [pid for state in states for pid in (state.get("root_pid"), state.get("backend_pid")) if pid]
        cleanup = {"cli_processes_exited": all(command.poll() is not None for command in commands),
                   "peer_processes_exited": all(server.poll() is not None for server in servers), "root_and_backend_pids_absent": all(absent(pid) for pid in owned_pids),
                   "all_sessions_finished": len(states) == 6 and all(state.get("state") == "finished" for state in states),
                   "backend_secret_configs_removed": not any(run.glob("state-*/sessions/*/backend.private.json")),
                   "receiver_threads_stopped": all(not receiver.thread.is_alive() and not any(worker.is_alive() for worker in receiver.workers) for receiver in receivers)}
        passed = error is None and len(results) == 6 and all(value["cli_exit"] == 0 and value["body_matches_profile"] and value["correct_receiver_requests"] == 1 and value["other_receiver_requests"] == 0 and value["paired_overlap"] for value in results) and all(cleanup.values())
        hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [ROOT / "bin/in-vpn", Path(__file__).resolve(), *sorted((ROOT / "src/invpn").glob("*.py"))]}
        summary = {"scope": "product CLI proxy mode; two independent actual local WireGuard peers; no external VPN exit, system DNS or crash containment claim",
                   "passed": passed, "error": error, "pairs": 3, "observed_requests": len(results), "results": results,
                   "receiver_requests": [request for receiver in receivers for request in receiver.requests], "cleanup": cleanup, "source_sha256": hashes}
        write_private(run / "observations.private.json", json.dumps(raw, indent=2))
        write_private(run / "summary.json", json.dumps(summary, indent=2))
        print(json.dumps({"run": str(run), **summary}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
