import json
import os
import select
import socket
import subprocess
import time

HOST = '/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility'


def execute(run):
    external = os.environ.get('INVPN_F04_DESTINATION') == 'external_https'
    binary = run.compile_c(run.root / 'test-support/probes' / ('https_probe.c' if external else 'socket_probe.c'), 'https-probe' if external else 'socket-probe', flags=['-lcurl'] if external else [])
    server = socket.socket(); server.bind(('127.0.0.1', 0)); server.listen(); server.settimeout(0.1)
    port = 443 if external else server.getsockname()[1]
    children, observations = {}, []
    def probe(label, phase):
        child = children[label]
        child.stdin.write(b'c'); child.stdin.flush()
        ready, _, _ = select.select([child.stdout], [], [], 3)
        if not ready: raise TimeoutError('socket probe did not respond')
        result = json.loads(child.stdout.readline())
        if external:
            observations.append({'phase': phase, 'process': label, 'pid': child.pid, 'probe': result, 'received': result['curl_result'] == 0 and result['http_status'] == 200, 'observation_kind': 'TLS-verified HTTPS response; not remote server logs', 'time': time.time()})
            return
        payload = None
        try:
            peer, _ = server.accept()
            with peer: peer.settimeout(1); payload = peer.recv(256).decode()
        except socket.timeout: pass
        observations.append({'phase': phase, 'process': label, 'pid': child.pid, 'probe': result, 'received': payload == label, 'unexpected_payload': payload is not None and payload != label, 'time': time.time()})
    try:
        children = {label: subprocess.Popen([str(binary)] if external else [str(binary), 'controlled', '127.0.0.1', str(port), label], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env) for label in ['A', 'B']}
        for label in children: probe(label, 'before_provider')
        run.command([HOST, 'start', port, children['B'].pid, '1.1.1.1' if external else '127.0.0.1'], check=True, timeout=180)
        for _ in range(30):
            response = run.command([HOST, 'status'], timeout=5)
            if response.returncode == 0 and response.stdout.startswith('{') and json.loads(response.stdout).get('ready'): break
            time.sleep(0.2)
        else: raise RuntimeError('provider not ready')
        state = json.loads(response.stdout)
        for _ in range(2):
            for label in children: probe(label, 'provider_active')
        active = [o for o in observations if o['phase'] == 'provider_active']
        if not all(o['received'] == (o['process'] == 'A') for o in active): raise RuntimeError('control did not establish selective TCP blocking; crash not injected')
        run.command([HOST, 'events'], name='before-crash-events.json', check=True, timeout=5)
        requested_at = time.time()
        acknowledged = False
        try:
            response = run.command([HOST, 'crash'], check=True, timeout=15)
            acknowledged = response.stdout.strip() == 'test_crash_scheduled'
        except subprocess.TimeoutExpired:
            # The provider may abort before its asynchronous IPC reply arrives.
            # A timeout is never proof of a crash; verify the process separately.
            pass
        run.save('crash.json', {'requested_at': requested_at, 'reply_checked_at': time.time(), 'acknowledged': acknowledged, 'provider_pid': state['providerPID']})
        time.sleep(0.5)
        gone = run.command(['ps', '-p', state['providerPID'], '-o', 'pid=,stat=,comm='], name='provider-after-crash.json')
        if gone.returncode != 1 or gone.stdout.strip(): raise RuntimeError('provider disappearance not observed; crash outcome unknown')
        for _ in range(10):
            for label in children: probe(label, 'after_crash')
            time.sleep(0.05)
        run.save('observations.json', observations)
    finally:
        for child in children.values():
            if child.poll() is None:
                try: child.communicate(b'q', timeout=3)
                except subprocess.TimeoutExpired: child.kill(); child.communicate(timeout=3)
        server.close()
        run.save('observations.json', observations)
        cleanup = run.command([HOST, 'remove'], timeout=10)
        run.save('cleanup.json', {'probe_processes_exited': all(c.poll() is not None for c in children.values()), 'receiver_closed': True, 'configuration_absent': cleanup.returncode == 0 or cleanup.stdout.strip() == 'no_configuration', 'extension_remains_installed': True})
    return {'scope': 'F04 one intentional abort, persistent known A/B processes, fresh TCP; no independent guard', 'destination': 'external HTTPS 1.1.1.1 or observed NAT64 equivalent' if external else 'IPv4 loopback receiver', 'observations': observations, 'B_direct_receipts_after_crash': sum(o['phase'] == 'after_crash' and o['process'] == 'B' and o['received'] for o in observations), 'unverified': ['UDP crash', 'existing connections', 'other IPv6 paths', 'independent guard', '20 repetitions', 'VPN forwarding', 'external receiver logs/packet capture']}
