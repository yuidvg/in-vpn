"""Real local WireGuard pairs, transparent TCP/UDP, DNS answer/cache experiment."""
import concurrent.futures
import importlib.util
import ipaddress
import os
import json
import socket
import struct
import subprocess
import threading
import time
import uuid

HOST = '/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility'


def load(run):
    spec = importlib.util.spec_from_file_location('fixtures', run.root / 'test-support/network/fixtures.py')
    fixtures = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)
    return fixtures


class Receiver:
    def __init__(self, label, address):
        self.label, self.address = label, address
        self.events = []; self.stop = threading.Event()
        self.tcp = socket.socket(); self.tcp.bind(('127.0.0.1', 0)); self.tcp.listen(); self.tcp.settimeout(.2)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.udp.bind(('127.0.0.1', 0)); self.udp.settimeout(.2)
        self.threads = [threading.Thread(target=self.serve_tcp, daemon=True), threading.Thread(target=self.serve_udp, daemon=True)]
        for t in self.threads: t.start()
    def serve_tcp(self):
        while not self.stop.is_set():
            try: conn, _ = self.tcp.accept()
            except socket.timeout: continue
            except OSError: return
            with conn:
                conn.settimeout(2)
                try:
                    request = conn.recv(8192)
                    self.events.append({'proto': 'tcp', 'request': request.decode(errors='replace')})
                    body = self.label.encode()
                    conn.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
                except OSError: pass
    def serve_udp(self):
        while not self.stop.is_set():
            try: data, peer = self.udp.recvfrom(65535)
            except socket.timeout: continue
            except OSError: return
            if len(data) >= 12 and not (struct.unpack('!H', data[2:4])[0] & 0x8000) and data[4:6] == b'\x00\x01':
                pos = 12; labels = []
                while data[pos]:
                    n = data[pos]; labels.append(data[pos+1:pos+1+n].decode()); pos += 1+n
                pos += 1
                qtype, qclass = struct.unpack('!HH', data[pos:pos+4])
                self.events.append({'proto': 'dns', 'query': '.'.join(labels), 'qtype': qtype, 'answer': self.address})
                question = data[12:pos+4]
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, int(os.environ.get("INVPN_DNS_TTL", "120")), 4) + socket.inet_aton(self.address) if qtype == 1 else b''
                response = data[:2] + struct.pack('!5H', 0x8180, 1, int(bool(answer)), 0, 0) + question + answer
            else:
                self.events.append({'proto': 'udp', 'payload': data.decode(errors='replace')}); response = data
            self.udp.sendto(response, peer)
    def close(self):
        self.stop.set(); self.tcp.close(); self.udp.close()
        for t in self.threads: t.join(timeout=1)


def route(run, pid, bridge):
    path = run.path / f'route-{pid}.private.json'
    run.save(path.name, {'pid': pid, 'port': bridge.port, 'secret': bridge.secret})
    response = run.command([HOST, 'route', path], timeout=10, check=True)
    if response.stdout.strip() != 'route_registered': raise RuntimeError('route not acknowledged')


def start(run, ip, port, dns=True):
    run.command([HOST, 'start', port, 0, ip, 'dns' if dns else 'none'], timeout=180, check=True)
    for _ in range(40):
        response = run.command([HOST, 'status'], timeout=5)
        if response.returncode == 0 and response.stdout.startswith('{') and json.loads(response.stdout).get('ready'):
            time.sleep(.5); return
        time.sleep(.2)
    raise RuntimeError('Provider not ready')


def gated(run, args, bridge=None, prefix=()):
    process = subprocess.Popen([*prefix, '/bin/zsh', '-f', '-c', 'read -r gate; exec "$@"', 'probe', *map(str,args)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env)
    try:
        if bridge: route(run, process.pid, bridge)
        stdout, stderr = process.communicate(b'go\n', timeout=15)
        return {'pid': process.pid, 'returncode': process.returncode, 'stdout': stdout.decode(), 'stderr': stderr.decode()}
    finally:
        if process.poll() is None: process.kill(); process.communicate(timeout=3)


def paired(run, args, bridges):
    children = []
    try:
        for command, bridge in zip(args, bridges):
            child = subprocess.Popen(['/bin/zsh', '-f', '-c', 'read -r gate; exec "$@"', 'probe', *map(str,command)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env)
            children.append(child)
            if bridge: route(run, child.pid, bridge)
        for child in children: child.stdin.write(b'go\n'); child.stdin.flush()
        result = []
        for child in children:
            stdout, stderr = child.communicate(timeout=15)
            result.append({'pid': child.pid, 'returncode': child.returncode, 'stdout': stdout.decode(), 'stderr': stderr.decode()})
        return result
    finally:
        for child in children:
            if child.poll() is None: child.kill(); child.communicate(timeout=3)


def execute(run):
    f = load(run); receivers = []; vpns = []; observations = []; provider_events = []
    try:
        for label, address in [('vpn1', '192.0.2.11'), ('vpn2', '192.0.2.22')]:
            receiver = Receiver(label, address); receivers.append(receiver)
            vpns.append(f.LocalVPN(run, label, receiver.tcp.getsockname()[1], receiver.udp.getsockname()[1]))
        # Independent bridge-free validation that both cryptographic peers work.
        for i, vpn in enumerate(vpns):
            conn, _ = f.backend.socks(vpn.bridge.socks_port, vpn.bridge.password, 1, '10.77.0.99', 18080)
            with conn:
                conn.sendall(b'GET /backend-preflight HTTP/1.0\r\n\r\n'); reply = conn.recv(4096)
            if not reply.endswith(f'vpn{i+1}'.encode()): raise RuntimeError('WireGuard peer preflight failed')
        start(run, '10.77.0.99', 18080)
        probe = run.compile_c(run.root / 'test-support/probes/socket_probe.c', 'socket-probe')
        dns = run.compile_c(run.root / 'test-support/probes/dns_probe.c', 'dns-probe')
        for iteration in range(5):
            commands = [['/usr/bin/curl', '--disable', '--proxy', '', '--noproxy', '*', '-4', '--max-time', '8', '-sS', f'http://10.77.0.99:18080/pair-{iteration}-{i}'] for i in range(2)]
            for i, result in enumerate(paired(run, commands, [v.bridge for v in vpns])):
                observations.append({'case': 'simultaneous_tcp', 'vpn': i+1, 'iteration': iteration, **result})
            for i, vpn in enumerate(vpns):
                token = f'udp-vpn{i+1}-{iteration}'
                observations.append({'case': 'udp_echo', 'vpn': i+1, **gated(run, [probe, 'udp-roundtrip', '10.77.0.99', 18080, token], vpn.bridge)})
        # Fresh per-VPN names and explicit ordinary UDP DNS packets are positive controls.
        for i, vpn in enumerate(vpns):
            fresh = f'{uuid.uuid4().hex}.invpn-feasibility.example.com'
            observations.append({'case': 'standard_dns_fresh', 'vpn': i+1, 'name': fresh, **gated(run, [dns, fresh], vpn.bridge)})
            observations.append({'case': 'direct_dns_socket', 'vpn': i+1, **gated(run, ['/usr/bin/dig', '+tries=1', '+time=3', '+short', '@10.77.0.99', '-p', '18080', 'same.invpn-feasibility.example.com', 'A'], vpn.bridge)})
        # Same name sequential requests expose any shared system cache or coalescing.
        names = [f'{uuid.uuid4().hex}.invpn-feasibility.example.com' for _ in range(2)]
        for name, order in zip(names, [(0,1,0,1), (1,0,1,0)]):
            for i in order:
                observations.append({'case': 'standard_dns_shared_name', 'vpn': i+1, 'name': name, **gated(run, [dns, name], vpns[i].bridge)})
        observations.append({'case': 'outside_session_warm_dns', 'name': names[0], **gated(run, [dns, names[0]])})
        same = f'{uuid.uuid4().hex}.invpn-feasibility.example.com'
        for i, result in enumerate(paired(run, [[dns, same], [dns, same]], [v.bridge for v in vpns])):
            observations.append({'case': 'standard_dns_concurrent', 'vpn': i+1, 'name': same, **result})
        # Sandbox deny-new-network candidate must permit working NE forwarding to qualify.
        profile = run.path / 'deny-network.sb'; profile.write_text('(version 1)(allow default)(deny network-outbound)')
        observations.append({'case': 'sandbox_plus_relay', **gated(run, ['/usr/bin/curl', '--disable', '--proxy', '', '--noproxy', '*', '-4', '--max-time', '3', '-sS', 'http://10.77.0.99:18080/sandbox'], vpns[0].bridge, ['/usr/bin/sandbox-exec', '-f', str(profile)])})
        vpns[0].client.close()
        for i, vpn in enumerate(vpns):
            observations.append({'case': 'vpn1_backend_stopped', 'vpn': i+1, **gated(run, ['/usr/bin/curl', '--disable', '--proxy', '', '--noproxy', '*', '-4', '--max-time', '3', '-sS', 'http://10.77.0.99:18080/after-stop'], vpn.bridge)})
        event_response = run.command([HOST, 'events'], timeout=10, check=True); provider_events = json.loads(event_response.stdout)
        return {'scope': 'Two actual WireGuard tunnels with local peers; manual PID selection', 'observations': observations, 'receivers': [r.events for r in receivers], 'bridge_events': [v.bridge.events for v in vpns]}
    finally:
        run.save('observations.json', observations); run.save('provider-events.json', provider_events)
        run.save('receivers.json', [r.events for r in receivers]); run.save('bridge-events.json', [v.bridge.events for v in vpns])
        removed = run.command([HOST, 'remove'], timeout=15)
        for v in vpns: v.close()
        for r in receivers: r.close()
        run.save('cleanup.json', {'configuration_absent': removed.returncode == 0 or removed.stdout.strip() == 'no_configuration', 'owned_singbox_exited': all(v.client.process.poll() is not None and v.server.process.poll() is not None for v in vpns), 'receiver_threads_exited': all(not t.is_alive() for r in receivers for t in r.threads)})
