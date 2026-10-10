"""Real external VPN relay with unmodified curl and system getaddrinfo clients."""
import importlib.util
import ipaddress
import json
import socket
import subprocess
import time
import uuid


def execute(run):
    spec = importlib.util.spec_from_file_location('multi', run.root / 'experiments/F07-multiple-vpns/run.py')
    multi = importlib.util.module_from_spec(spec); spec.loader.exec_module(multi)
    f = multi.load(run); box = bridge = None; children = []; observations = []; events = []
    ip = socket.getaddrinfo('api.ipify.org', 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    command = ['/usr/bin/curl', '--disable', '--proxy', '', '--noproxy', '*', '-4', '--http1.1', '--resolve', f'api.ipify.org:443:{ip}', '--max-time', '10', '-sS', 'https://api.ipify.org']
    private = []
    def inspect(case, result, expected=None):
        private.append({'case': case, **result})
        address = None
        try:
            if result['returncode'] == 0: address = str(ipaddress.ip_address(result['stdout'].strip()))
        except ValueError: pass
        observations.append({'case': case, 'pid': result.get('pid'), 'returncode': result['returncode'], 'valid_ip_response': address is not None, 'matches_expected_exit': address == expected if expected else None})
        run.save('observations.json', observations); run.save('clients.private.json', private)
        return address
    try:
        box, bridge, dns_server = f.real_backend(run)
        normal = inspect('before_provider_normal', multi.gated(run, command))
        if not normal: raise RuntimeError('normal egress unavailable')
        reference = None
        attempts = []
        for attempt in range(3):
            try:
                conn, _ = f.backend.socks(bridge.socks_port, bridge.password, 1, ip, 443)
                reference = f.backend.trace(conn)
                attempts.append({'attempt': attempt, 'success': True}); break
            except OSError as error:
                attempts.append({'attempt': attempt, 'success': False, 'error': str(error)}); time.sleep(.5)
        run.save('reference-attempts.json', attempts)
        if reference is None: raise RuntimeError('VPN reference preflight failed')
        run.save('egress.private.json', {'normal': normal, 'vpn': reference})
        if normal == reference: raise RuntimeError('VPN exit not distinguishable')
        multi.start(run, ip, 443)
        for n in range(3):
            for label, result in zip(['A', 'B'], multi.paired(run, [command, command], [None, bridge])):
                inspect(f'active_{n}_{label}', result, normal if label == 'A' else reference)
        active = [x for x in observations if x['case'].startswith('active_')]
        if len(active) != 6 or not all(x['matches_expected_exit'] for x in active): raise RuntimeError('active control failed; no failure injection')
        dns = run.compile_c(run.root / 'test-support/probes/dns_probe.c', 'dns-probe')
        name = f'{uuid.uuid4().hex}.invpn-feasibility.example.com'
        try: observations.append({'case': 'standard_dns_over_real_vpn', **multi.gated(run, [dns, name], bridge)})
        except subprocess.TimeoutExpired: observations.append({'case': 'standard_dns_over_real_vpn', 'timed_out': True})
        run.save('observations.json', observations)
        active = [x for x in observations if x['case'].startswith('active_')]
        if len(active) != 6 or not all(x['matches_expected_exit'] for x in active): raise RuntimeError('active control failed; no failure injection')
        box.close()
        inspect('backend_stopped_A', multi.gated(run, command), normal)
        inspect('backend_stopped_B', multi.gated(run, command, bridge), reference)
        bridge.close()
        inspect('bridge_stopped_B', multi.gated(run, command, bridge), reference)
        # Register the next B before crashing, so classification is not added after failure.
        crash_probe = run.compile_c(run.root / 'test-support/probes/https_probe.c', 'crash-https', ['-lcurl'])
        child = subprocess.Popen([str(crash_probe), 'https://api.ipify.org', f'api.ipify.org:443:{ip}'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env)
        children.append(child); multi.route(run, child.pid, bridge)
        events = json.loads(run.command([multi.HOST, 'events'], timeout=10, check=True).stdout)
        state = json.loads(run.command([multi.HOST, 'status'], timeout=10, check=True).stdout)
        try: acknowledgement = run.command([multi.HOST, 'crash'], timeout=8)
        except subprocess.TimeoutExpired: acknowledgement = None
        time.sleep(.5)
        gone = run.command(['ps', '-p', str(state['providerPID']), '-o', 'pid='], name='provider-after-crash.json')
        if gone.returncode == 0: raise RuntimeError('crash not established')
        time.sleep(3)
        import select
        for index in range(10):
            child.stdin.write(b't'); child.stdin.flush()
            if not select.select([child.stdout], [], [], 6)[0]: raise TimeoutError('crash client reply absent')
            reply = json.loads(child.stdout.readline())
            observations.append({'case': 'provider_crashed_B', 'index': index, **reply})
            time.sleep(.1)
        child.communicate(b'q', timeout=3)
        run.save('crash.json', {'providerPID': state['providerPID'], 'provider_disappeared': gone.returncode != 0, 'acknowledged': acknowledgement is not None and acknowledgement.returncode == 0, 'B_registered_before_crash': True, 'delay_after_pid_disappearance_seconds': 3})
        return {'scope': 'manual PID transparent NE to authenticated local bridge to SOCKS to external WireGuard', 'bootstrap_dns': 'normal api.ipify.org lookup before protected client; clients use curl --resolve', 'observations': observations}
    finally:
        for child in children:
            if child.poll() is None: child.kill(); child.communicate(timeout=3)
        if not events:
            try:
                response = run.command([multi.HOST, 'events'], timeout=5)
                if response.returncode == 0: events = json.loads(response.stdout)
            except (subprocess.TimeoutExpired, json.JSONDecodeError): pass
        run.save('observations.json', observations); run.save('provider-events.json', events)
        if bridge: run.save('bridge-events.private.json', bridge.events); bridge.close()
        if box: box.close()
        removed = run.command([multi.HOST, 'remove'], timeout=15)
        run.save('cleanup.json', {'configuration_absent': removed.returncode == 0 or removed.stdout.strip() == 'no_configuration', 'owned_backend_exited': box is None or box.process.poll() is not None, 'clients_exited': all(c.poll() is not None for c in children)})
