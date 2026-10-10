"""Backend-only transport probe. This is not transparent process routing."""
import configparser
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import time


def exact(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part: raise OSError('unexpected EOF')
        data += part
    return data


def socks(port, password, command, host, remote_port):
    conn = socket.create_connection(('127.0.0.1', port), timeout=10)
    try:
        conn.sendall(b'\x05\x01\x02')
        if exact(conn, 2) != b'\x05\x02': raise OSError('SOCKS auth method rejected')
        secret = password.encode()
        conn.sendall(b'\x01\x05probe' + bytes([len(secret)]) + secret)
        if exact(conn, 2) != b'\x01\x00': raise OSError('SOCKS authentication rejected')
        conn.sendall(bytes([5, command, 0, 1]) + socket.inet_aton(host) + struct.pack('!H', remote_port))
        version, status, _, family = exact(conn, 4)
        if version != 5 or status: raise OSError(f'SOCKS reply status {status}')
        if family == 1: bound_host = socket.inet_ntoa(exact(conn, 4))
        elif family == 4: bound_host = socket.inet_ntop(socket.AF_INET6, exact(conn, 16))
        else: raise OSError('unexpected SOCKS bound address')
        bound_port = struct.unpack('!H', exact(conn, 2))[0]
        return conn, (bound_host, bound_port)
    except BaseException:
        conn.close()
        raise


def trace(conn):
    context = ssl.create_default_context()
    with context.wrap_socket(conn, server_hostname='api.ipify.org') as secure:
        secure.sendall(b'GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
        data = b''
        while len(data) < 32768:
            part = secure.recv(4096)
            if not part: break
            data += part
    lines = data.decode().splitlines()
    if not lines or ' 200 ' not in lines[0]: raise OSError('trace HTTP response not 200')
    address = data.decode().split('\r\n\r\n', 1)[1].strip()
    return str(ipaddress.ip_address(address))


def execute(run):
    import os, importlib.util
    if os.environ.get("INVPN_F05_MODE") == "transparent":
        spec = importlib.util.spec_from_file_location("transparent", run.root / "experiments/F05-vpn-forwarding/transparent.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module.execute(run)

    private = run.root / '.local/secrets/wg-CH-FREE-8.conf'
    config = configparser.ConfigParser()
    if not config.read(private): raise RuntimeError('WireGuard fixture missing')
    interface, peer = config['Interface'], config['Peer']
    # Avoid simultaneously roaming an existing mirror tunnel that shares this key.
    mirror = Path.home() / '.config/mirror/vpn.json'
    if mirror.is_file():
        existing = json.loads(mirror.read_text())
        if any(item.get('private_key') == interface['PrivateKey'] for item in existing.get('endpoints', []) + existing.get('outbounds', [])):
            raise RuntimeError('Fixture shares mirror private key; use a dedicated test key')
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    password = secrets.token_hex(16)
    host, endpoint_port = peer['Endpoint'].rsplit(':', 1)
    ipaddress.ip_address(host.strip('[]')) # avoid DNS outside the VPN for peer lookup
    allowed_ips = [item.strip() for item in peer['AllowedIPs'].split(',')]
    endpoint = {'type': 'wireguard', 'tag': 'test-wg', 'system': False, 'address': [item.strip() for item in interface['Address'].split(',')], 'private_key': interface['PrivateKey'], 'peers': [{'address': host.strip('[]'), 'port': int(endpoint_port), 'public_key': peer['PublicKey'], 'allowed_ips': allowed_ips, 'persistent_keepalive_interval': int(peer.get('PersistentKeepalive', '0'))}]}
    if 'PresharedKey' in peer: endpoint['peers'][0]['pre_shared_key'] = peer['PresharedKey']
    settings = {'log': {'level': 'warn', 'timestamp': True}, 'inbounds': [{'type': 'socks', 'tag': 'test-socks', 'listen': '127.0.0.1', 'listen_port': port, 'users': [{'username': 'probe', 'password': password}]}], 'endpoints': [endpoint], 'route': {'final': 'test-wg'}}
    run.save('private-sing-box.json', settings)
    config_path = run.path / 'private-sing-box.json'
    run.command(['sing-box', 'check', '-c', config_path], check=True)
    observations = []
    # This explicit test bootstrap uses the normal system resolver. It is not
    # attributed to a protected session or reported as VPN-isolated DNS.
    trace_ip = socket.getaddrinfo('api.ipify.org', 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    process = None
    baseline_ip, tunnel_ip = None, None
    try:
        baseline_ip = trace(socket.create_connection((trace_ip, 443), timeout=10))
        observations.append({'case': 'normal_tcp_tls_trace', 'success': True})
        with (run.path / 'sing-box.log').open('w') as log:
            process = subprocess.Popen(['sing-box', 'run', '-c', str(config_path)], stdout=log, stderr=log, env=run.env)
            for _ in range(60):
                if process.poll() is not None: raise RuntimeError('sing-box exited; see local log')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1): pass
                    break
                except OSError: time.sleep(0.1)
            else: raise TimeoutError('sing-box listener did not become ready')
            try:
                conn, _ = socks(port, password, 1, trace_ip, 443)
                tunnel_ip = trace(conn)
                observations.append({'case': 'socks_connect_wireguard_tls_trace', 'success': True, 'exit_differs_from_normal': baseline_ip != tunnel_ip})
            except Exception as error:
                observations.append({'case': 'socks_connect_wireguard_tls_trace', 'success': False, 'error': str(error)})
            for dns in [item.strip() for item in interface.get('DNS', '').split(',') if item.strip()]:
                if ipaddress.ip_address(dns).version != 4: continue
                control, relay = socks(port, password, 3, '0.0.0.0', 0)
                with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind(('127.0.0.1', 0)); udp.settimeout(10)
                    query_id = secrets.randbelow(65536)
                    query = struct.pack('!6H', query_id, 0x0100, 1, 0, 0, 0) + b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
                    udp.sendto(b'\x00\x00\x00\x01' + socket.inet_aton(dns) + struct.pack('!H', 53) + query, relay)
                    response, _ = udp.recvfrom(4096)
                    if response[:4] != b'\x00\x00\x00\x01': raise OSError('invalid SOCKS UDP framing')
                    reply_id, flags, questions, answers, _, _ = struct.unpack('!6H', response[10:22])
                    valid = reply_id == query_id and bool(flags & 0x8000) and flags & 15 == 0 and answers > 0 and response[4:8] == socket.inet_aton(dns)
                    observations.append({'case': 'socks_udp_associate_wireguard_configured_dns', 'success': valid, 'rcode': flags & 15, 'answers': answers, 'scope': 'explicit DNS packet; not getaddrinfo/system DNS'})
            process.terminate(); process.wait(timeout=5)
            try:
                conn, _ = socks(port, password, 1, trace_ip, 443)
                conn.close()
                observations.append({'case': 'backend_stopped', 'new_connection_refused': False})
            except OSError:
                observations.append({'case': 'backend_stopped', 'new_connection_refused': True})
            after = trace(socket.create_connection((trace_ip, 443), timeout=10))
            observations.append({'case': 'normal_tcp_after_cleanup', 'success': True, 'same_normal_exit': after == baseline_ip})
    except Exception as error:
        observations.append({'case': 'error', 'type': type(error).__name__, 'message': str(error)})
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        run.save('cleanup.json', {'owned_singbox_exited': process is None or process.poll() is not None, 'system_routes_or_dns_changed': False, 'persistent_system_changes': False})
    # Egress addresses are kept locally, excluded from reviewed evidence.
    run.save('egress.private.json', {'normal_ip': baseline_ip, 'tunnel_ip': tunnel_ip})
    return {'scope': 'F05 backend-only SOCKS TCP/UDP over real WireGuard; no NE provider', 'bootstrap_dns': 'api.ipify.org resolved normally before the tunnel probe', 'observations': observations, 'unverified': ['same-binary transparent selection', 'standard DNS attribution', 'provider crash', 'external receiver logs/packet capture', 'IPv6', 'multiple destinations/MTU/half-close', 'multiple VPNs']}
