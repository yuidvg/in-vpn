"""Owned, bounded network fixtures. No global routes, DNS, or existing VPN edits."""
import base64
import configparser
import importlib.util
import ipaddress
import json
import secrets
import select
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('backend', ROOT / 'experiments/F05-vpn-forwarding/run.py')
backend = importlib.util.module_from_spec(spec); spec.loader.exec_module(backend)


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


def address_bytes(host, remote_port):
    ip = ipaddress.ip_address(host)
    # Restrict NAT64 translation to the exact observed well-known prefix.
    if ip.version == 6 and ip in ipaddress.ip_network('64:ff9b::/96'):
        ip = ipaddress.ip_address(int(ip) & 0xffffffff)
    return bytes([1 if ip.version == 4 else 4]) + ip.packed + struct.pack('!H', int(remote_port))


class SingBox:
    def __init__(self, run, name, settings):
        self.path = run.path / f'{name}.private.json'
        run.save(self.path.name, settings)
        run.command(['sing-box', 'check', '-c', self.path], check=True)
        self.log = (run.path / f'{name}.private.log').open('w')
        self.process = subprocess.Popen(['sing-box', 'run', '-c', self.path], stdout=self.log, stderr=self.log, env=run.env)
        time.sleep(.3)
        if self.process.poll() is not None: raise RuntimeError(f'{name} exited')
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=3)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=3)
        self.log.close()


class Bridge:
    def __init__(self, socks_port, password, dns=None):
        self.socks_port, self.password, self.dns = socks_port, password, dns
        self.test_destination = None
        self.secret = secrets.token_hex(24)
        self.server = socket.socket(); self.server.bind(('127.0.0.1', 0)); self.server.listen(); self.server.settimeout(.2)
        self.port = self.server.getsockname()[1]
        self.closed = threading.Event(); self.events = []; self.connections = set(); self.workers = []
        self.thread = threading.Thread(target=self.accept, daemon=True); self.thread.start()
    def accept(self):
        while not self.closed.is_set():
            try: client, _ = self.server.accept()
            except socket.timeout: continue
            except OSError: return
            self.connections.add(client)
            worker = threading.Thread(target=self.serve, args=(client,), daemon=True)
            self.workers.append(worker); worker.start()
    def serve(self, client):
        control = udp = None
        try:
            client.settimeout(15)
            header = b''
            while not header.endswith(b'\n') and len(header) < 4096: header += backend.exact(client, 1)
            info = json.loads(header)
            if not secrets.compare_digest(info['secret'], self.secret): raise ValueError('auth failed')
            if info['proto'] == 'tcp':
                host = str(ipaddress.ip_address(address_bytes(self.test_destination or info['host'], info['port'])[1:-2]))
                control, _ = backend.socks(self.socks_port, self.password, 1, host, int(info['port']))
                self.events.append({'proto': 'tcp', 'host': host, 'port': int(info['port']), 'connected': True})
                client.sendall(b'\0'); client.settimeout(None); control.settimeout(None)
                read_sides = [client, control]
                while read_sides and not self.closed.is_set():
                    ready, _, _ = select.select(read_sides, [], [], .2)
                    for source in ready:
                        target = control if source is client else client
                        data = source.recv(65536)
                        if data: target.sendall(data)
                        else: read_sides.remove(source); target.shutdown(socket.SHUT_WR)
            else:
                control, relay = backend.socks(self.socks_port, self.password, 3, '0.0.0.0', 0)
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('127.0.0.1', 0)); udp.settimeout(5)
                client.sendall(b'\0')
                while not self.closed.is_set():
                    size = struct.unpack('!I', backend.exact(client, 4))[0]
                    if not 0 < size <= 100000: raise ValueError('oversized datagram')
                    item = json.loads(backend.exact(client, size))
                    host = self.dns if int(item['port']) == 53 and self.dns else item['host']
                    payload = base64.b64decode(item['payload'], validate=True)
                    udp.sendto(b'\0\0\0' + address_bytes(host, item['port']) + payload, relay)
                    response, _ = udp.recvfrom(65535)
                    if response[:4] != b'\0\0\0\1': raise ValueError('unsupported UDP reply')
                    reply = response[10:]
                    self.events.append({'proto': 'udp', 'port': int(item['port']), 'request_bytes': len(payload), 'response_bytes': len(reply)})
                    frame = json.dumps(dict(item, payload=base64.b64encode(reply).decode())).encode()
                    client.sendall(struct.pack('!I', len(frame)) + frame)
        except Exception as error:
            self.events.append({'error': type(error).__name__, 'message': str(error)})
        finally:
            for s in [client, control, udp]:
                if s: s.close()
            self.connections.discard(client)
    def close(self):
        self.closed.set(); self.server.close()
        for conn in list(self.connections):
            try: conn.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        self.thread.join(timeout=1)
        for t in self.workers: t.join(timeout=1)


def real_backend(run):
    config = configparser.ConfigParser(); config.read(ROOT / '.local/secrets/wg-CH-FREE-8.conf')
    interface, peer = config['Interface'], config['Peer']
    mirror = Path.home() / '.config/mirror/vpn.json'
    if mirror.exists():
        existing = json.loads(mirror.read_text())
        if any(x.get('private_key') == interface['PrivateKey'] for x in existing.get('endpoints', []) + existing.get('outbounds', [])):
            raise RuntimeError('Fixture shares active mirror key')
    host, remote_port = peer['Endpoint'].rsplit(':', 1)
    ipaddress.ip_address(host.strip('[]'))
    endpoint = {'type': 'wireguard', 'tag': 'wg', 'system': False, 'mtu': 1280, 'address': [x.strip() for x in interface['Address'].split(',')], 'private_key': interface['PrivateKey'], 'peers': [{'address': host.strip('[]'), 'port': int(remote_port), 'public_key': peer['PublicKey'], 'allowed_ips': [x.strip() for x in peer['AllowedIPs'].split(',')]}]}
    if 'PresharedKey' in peer: endpoint['peers'][0]['pre_shared_key'] = peer['PresharedKey']
    socks_port, password = port(), secrets.token_hex(16)
    box = SingBox(run, 'external-backend', {'log': {'level': 'debug'}, 'endpoints': [endpoint], 'inbounds': [socks_inbound(socks_port, password)], 'route': {'final': 'wg'}})
    dns = interface['DNS'].split(',')[0].strip()
    return box, Bridge(socks_port, password, dns), dns


def socks_inbound(socks_port, password):
    return {'type': 'socks', 'listen': '127.0.0.1', 'listen_port': socks_port, 'users': [{'username': 'probe', 'password': password}]}


class LocalVPN:
    """Actual encrypted WireGuard pairs; peers run locally, not internet VPN exits."""
    def __init__(self, run, label, tcp_port, udp_port):
        pairs = []
        for _ in range(2):
            result = subprocess.run(['sing-box', 'generate', 'wg-keypair'], capture_output=True, text=True, check=True, env=run.env)
            pairs.append(dict(line.split(': ', 1) for line in result.stdout.strip().splitlines()))
        server_port, socks_port, password = port(socket.SOCK_DGRAM), port(), secrets.token_hex(16)
        server_ep = {'type': 'wireguard', 'tag': 'server', 'system': False, 'listen_port': server_port, 'address': ['10.77.0.1/24'], 'private_key': pairs[0]['PrivateKey'], 'peers': [{'public_key': pairs[1]['PublicKey'], 'allowed_ips': ['10.77.0.2/32']}]}
        client_ep = {'type': 'wireguard', 'tag': 'client', 'system': False, 'address': ['10.77.0.2/24'], 'private_key': pairs[1]['PrivateKey'], 'peers': [{'address': '127.0.0.1', 'port': server_port, 'public_key': pairs[0]['PublicKey'], 'allowed_ips': ['10.77.0.0/24']}]}
        rules = [{'network': proto, 'action': 'route', 'outbound': 'receiver', 'override_address': '127.0.0.1', 'override_port': p} for proto, p in [('tcp', tcp_port), ('udp', udp_port)]]
        self.server = SingBox(run, label + '-server', {'log': {'level': 'debug'}, 'endpoints': [server_ep], 'outbounds': [{'type': 'direct', 'tag': 'receiver'}], 'route': {'rules': rules, 'final': 'receiver'}})
        try:
            self.client = SingBox(run, label + '-client', {'log': {'level': 'debug'}, 'endpoints': [client_ep], 'inbounds': [socks_inbound(socks_port, password)], 'route': {'final': 'client'}})
        except BaseException: self.server.close(); raise
        self.bridge = Bridge(socks_port, password, '10.77.0.53')
    def close(self):
        self.bridge.close(); self.client.close(); self.server.close()
