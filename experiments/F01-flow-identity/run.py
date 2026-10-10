import json
import hashlib
import os
import select
import socket
import subprocess
import time
import threading


HOST = '/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility'


def loopback(run):
    binary = run.compile_c(run.root / 'test-support/probes/socket_probe.c', 'socket-probe')
    tcp = socket.socket(); tcp.bind(('127.0.0.1', 0)); tcp.listen(); tcp.settimeout(0.1)
    port = tcp.getsockname()[1]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('127.0.0.1', port)); udp.settimeout(0.1)
    children, observations, events = {}, [], []
    config_created = False

    def send(label, protocol, phase):
        child = children[label]
        child.stdin.write(b't' if protocol == 'tcp' else b'u'); child.stdin.flush()
        ready, _, _ = select.select([child.stdout], [], [], 3)
        if not ready: raise TimeoutError('probe did not finish socket operation')
        line = child.stdout.readline()
        probe = json.loads(line)
        data = None
        try:
            if protocol == 'tcp':
                connection, _ = tcp.accept()
                with connection:
                    connection.settimeout(1); data = connection.recv(1024)
            else: data, _ = udp.recvfrom(1024)
        except socket.timeout: pass
        observations.append({'phase': phase, 'process': label, 'pid': child.pid, 'protocol': protocol, 'probe': probe, 'received': data == label.encode(), 'unexpected_payload': data is not None and data != label.encode()})

    try:
        for label in ['A', 'B']:
            children[label] = subprocess.Popen(['/bin/zsh', '-f', '-c', 'exec "$@"', 'probe-shell', str(binary), 'controlled', '127.0.0.1', str(port), label], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env)
        for label in children:
            for protocol in ['tcp', 'udp']: send(label, protocol, 'before_provider')
        config_created = True
        run.command([HOST, 'start', port, children['B'].pid], check=True, timeout=60)
        for _ in range(15):
            result = run.command([HOST, 'events'], timeout=5)
            if result.returncode == 0 and result.stdout.strip().startswith('['): break
            time.sleep(0.2)
        else: raise RuntimeError('provider did not answer; no flow test result inferred')
        # Explore before spending time on the 100-pair confirmation.
        for _ in range(3):
            for label in children:
                for protocol in ['tcp', 'udp']: send(label, protocol, 'provider_active')
        result = run.command([HOST, 'events'], timeout=5, check=True)
        events = json.loads(result.stdout)
        run.save('provider-events.json', events)
        run.command([HOST, 'stop'], timeout=5, check=True)
        time.sleep(0.5)
        for label in children:
            for protocol in ['tcp', 'udp']: send(label, protocol, 'after_stop')
    finally:
        for child in children.values():
            if child.poll() is None:
                try: child.communicate(b'q', timeout=3)
                except subprocess.TimeoutExpired: child.kill(); child.communicate(timeout=3)
        tcp.close(); udp.close()
        cleanup = run.command([HOST, 'remove'], timeout=10) if config_created else None
        run.save('observations.json', observations)
        run.save('cleanup.json', {'probe_processes_exited': all(child.poll() is not None for child in children.values()), 'receivers_closed': True, 'configuration_removed': cleanup.returncode == 0 if cleanup else None, 'extension_remains_installed': True})
    return {'scope': 'F01 same binary A/B, manual root selection, IPv4 loopback only; F04 graceful stop baseline', 'observations': observations, 'provider_event_count': len(events), 'unverified': ['external IP path', 'VPN forwarding', 'descendant tracking', 'DNS', '100 paired confirmations', 'provider crash']}


def external_tcp(run):
    observations, events = [], []
    curl = '/usr/bin/curl'
    run.manifest['probe_sha256'] = hashlib.sha256(open(curl, 'rb').read()).hexdigest()
    children = {}
    try:
        run.command([HOST, 'start', 443, 0, '1.1.1.1'], check=True, timeout=60)
        for _ in range(30):
            response = run.command([HOST, 'status'], timeout=5)
            if response.returncode == 0 and response.stdout.strip().startswith('{') and json.loads(response.stdout).get('ready'): break
            time.sleep(0.2)
        else: raise RuntimeError('no provider control response')
        time.sleep(2)
        for iteration in range(3):
            children = {}
            for label in ['A', 'B']:
                children[label] = subprocess.Popen(['/bin/zsh', '-f', '-c', 'read -r gate; exec "$@"', 'probe-shell', curl, '--disable', '--silent', '--show-error', '--http1.1', '--noproxy', '*', '--connect-timeout', '3', '--max-time', '6', '--output', '/dev/null', '--write-out', '%{remote_ip}:%{remote_port}', 'https://1.1.1.1/cdn-cgi/trace'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env)
            response = run.command([HOST, 'select', children['B'].pid], check=True, timeout=5)
            if response.stdout.strip() != 'selected_test_pid': raise RuntimeError('test PID not acknowledged')
            for child in children.values(): child.stdin.write(b'go\n'); child.stdin.flush()
            for label, child in children.items():
                stdout, stderr = child.communicate(timeout=10)
                observations.append({'iteration': iteration, 'process': label, 'launcher_pid': child.pid, 'returncode': child.returncode, 'stdout': stdout.decode(), 'stderr': stderr.decode()})
            response = run.command([HOST, 'events'], check=True, timeout=5)
            events.append({'iteration': iteration, 'events': json.loads(response.stdout)})
            run.save('observations.json', observations)
            run.save('provider-events.json', events)
    finally:
        for child in children.values():
            if child.poll() is None: child.kill(); child.communicate(timeout=3)
        try:
            cleanup = run.command([HOST, 'remove'], timeout=10)
            removed = cleanup.returncode == 0 or cleanup.stdout.strip() == 'no_configuration'
            run.save('cleanup.json', {'probe_processes_exited': all(c.poll() is not None for c in children.values()), 'configuration_absent': removed, 'extension_remains_installed': True})
        finally:
            run.save('observations.json', observations)
            run.save('provider-events.json', events)
    event_count = sum(len(item['events']) for item in events)
    return {'scope': 'F01 same system curl binary, simultaneous A/B over external IPv4 TCP; known root PIDs only', 'conclusion': 'inconclusive: no flow callback' if event_count == 0 else 'callbacks observed; inspect PID correlation and A/B results', 'observations': observations, 'provider_events': events, 'unverified': ['UDP', 'VPN forwarding', 'descendants', 'DNS', '100 independent paired runs', 'remote receiver logs/packet capture', 'crash containment']}


def external_sockets(run):
    binary = run.compile_c(run.root / 'test-support/probes/socket_probe.c', 'socket-probe')
    children, observations, events = {}, [], []
    try:
        run.command([HOST, 'start', 443, 0, '1.1.1.1'], check=True, timeout=60)
        for _ in range(30):
            response = run.command([HOST, 'status'], timeout=5)
            if response.returncode == 0 and response.stdout.strip().startswith('{') and json.loads(response.stdout).get('ready'): break
            time.sleep(0.2)
        else: raise RuntimeError('no provider control response')
        time.sleep(2)
        for protocol in ['tcp', 'udp']:
            for label in ['A', 'B']:
                children[label] = subprocess.Popen(['/bin/zsh', '-f', '-c', 'read -r gate; exec "$@"', 'probe-shell', str(binary), protocol, '1.1.1.1', '443', label], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env)
            response = run.command([HOST, 'select', children['B'].pid], check=True, timeout=5)
            if response.stdout.strip() != 'selected_test_pid': raise RuntimeError('test PID not acknowledged')
            for child in children.values(): child.stdin.write(b'go\n'); child.stdin.flush()
            for label, child in children.items():
                stdout, stderr = child.communicate(timeout=8)
                observations.append({'protocol': protocol, 'process': label, 'launcher_pid': child.pid, 'returncode': child.returncode, 'stdout': stdout.decode(), 'stderr': stderr.decode()})
            time.sleep(0.2)
            response = run.command([HOST, 'events'], check=True, timeout=5)
            events.append({'protocol': protocol, 'events': json.loads(response.stdout)})
            run.save('observations.json', observations)
            run.save('provider-events.json', events)
    finally:
        for child in children.values():
            if child.poll() is None: child.kill(); child.communicate(timeout=3)
        try:
            cleanup = run.command([HOST, 'remove'], timeout=10)
            run.save('cleanup.json', {'probe_processes_exited': all(c.poll() is not None for c in children.values()), 'configuration_absent': cleanup.returncode == 0 or cleanup.stdout.strip() == 'no_configuration', 'extension_remains_installed': True})
        finally:
            run.save('observations.json', observations)
            run.save('provider-events.json', events)
    return {'scope': 'F01 same C socket probe A/B over external IPv4 TCP and UDP; send result is local socket acceptance, not remote receipt', 'observations': observations, 'provider_events': events, 'unverified': ['remote receipt', 'VPN forwarding', 'descendants', 'DNS', 'crash containment']}


def client_matrix(run):
    binary = run.compile_c(run.root / 'test-support/probes/socket_probe.c', 'socket-probe')
    base = ['/usr/bin/curl', '--disable', '--silent', '--show-error', '--http1.1', '--noproxy', '*', '--connect-timeout', '3', '--max-time', '6', '--output', '/dev/null', '--write-out', '%{remote_ip}:%{remote_port}', 'https://1.1.1.1/cdn-cgi/trace']
    cases = [('c_tcp', [str(binary), 'tcp', '1.1.1.1', '443', 'probe']), ('system_curl', base), ('system_curl_ipv4', base[:1] + ['--ipv4'] + base[1:]), ('system_nc', ['/usr/bin/nc', '-z', '-G', '3', '1.1.1.1', '443']), ('c_tcp_again', [str(binary), 'tcp', '1.1.1.1', '443', 'probe'])]
    children, observations, events = {}, [], []
    try:
        run.command([HOST, 'start', 443, 0, '1.1.1.1'], check=True, timeout=60)
        for _ in range(30):
            response = run.command([HOST, 'status'], timeout=5)
            if response.returncode == 0 and response.stdout.strip().startswith('{') and json.loads(response.stdout).get('ready'): break
            time.sleep(0.2)
        else: raise RuntimeError('no provider control response')
        time.sleep(2)
        for case, command in cases:
            children = {label: subprocess.Popen(['/bin/zsh', '-f', '-c', 'read -r gate; exec "$@"', 'probe-shell', *command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env) for label in ['A', 'B']}
            response = run.command([HOST, 'select', children['B'].pid], check=True, timeout=5)
            if response.stdout.strip() != 'selected_test_pid': raise RuntimeError('test PID not acknowledged')
            for child in children.values(): child.stdin.write(b'go\n'); child.stdin.flush()
            for label, child in children.items():
                stdout, stderr = child.communicate(timeout=8)
                observations.append({'case': case, 'process': label, 'launcher_pid': child.pid, 'returncode': child.returncode, 'stdout': stdout.decode(), 'stderr': stderr.decode()})
            response = run.command([HOST, 'events'], check=True, timeout=5)
            events.append({'case': case, 'events': json.loads(response.stdout)})
            run.save('observations.json', observations)
            run.save('provider-events.json', events)
    finally:
        for child in children.values():
            if child.poll() is None: child.kill(); child.communicate(timeout=3)
        try:
            cleanup = run.command([HOST, 'remove'], timeout=10)
            run.save('cleanup.json', {'probe_processes_exited': all(c.poll() is not None for c in children.values()), 'configuration_absent': cleanup.returncode == 0 or cleanup.stdout.strip() == 'no_configuration', 'extension_remains_installed': True})
        finally:
            run.save('observations.json', observations)
            run.save('provider-events.json', events)
    return {'scope': 'F01 client API comparison in one provider lifetime, same binary A/B for each case', 'observations': observations, 'provider_events': events}


def loopback_confirm(run):
    count = int(os.environ.get('INVPN_F01_PAIRS', '5'))
    if not 1 <= count <= 100: raise ValueError('pairs must be 1..100')
    binary = run.compile_c(run.root / 'test-support/probes/socket_probe.c', 'socket-probe')
    tcp = socket.socket(); tcp.bind(('127.0.0.1', 0)); tcp.listen(); tcp.settimeout(0.1)
    port = tcp.getsockname()[1]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('127.0.0.1', port)); udp.settimeout(0.1)
    received, receiver_errors = [], []
    guard, stopped = threading.Lock(), threading.Event()
    def receive(protocol, server):
        while not stopped.is_set():
            try:
                if protocol == 'tcp':
                    peer, _ = server.accept()
                    with peer:
                        peer.settimeout(1); data = peer.recv(256)
                else:
                    data, address = server.recvfrom(256); server.sendto(data, address)
                with guard: received.append({'protocol': protocol, 'payload': data.decode(), 'time': time.time()})
            except socket.timeout: continue
            except Exception as error:
                with guard: receiver_errors.append(repr(error))
                return
    threads = [threading.Thread(target=receive, args=(proto, server)) for proto, server in [('tcp', tcp), ('udp', udp)]]
    for thread in threads: thread.start()
    children, observations, events = {}, [], []
    try:
        run.command([HOST, 'start', port, 0, '127.0.0.1'], check=True, timeout=60)
        for _ in range(30):
            response = run.command([HOST, 'status'], timeout=5)
            if response.returncode == 0 and response.stdout.strip().startswith('{') and json.loads(response.stdout).get('ready'): break
            time.sleep(0.2)
        else: raise RuntimeError('no provider control response')
        for iteration in range(count):
            for protocol in ['tcp', 'udp']:
                children = {}
                for label in ['A', 'B']:
                    token = f'{iteration}-{protocol}-{label}'
                    command = [str(binary), 'udp-roundtrip' if protocol == 'udp' else 'tcp', '127.0.0.1', str(port), token]
                    children[label] = subprocess.Popen(['/bin/zsh', '-f', '-c', 'read -r gate; exec "$@"', 'probe-shell', *command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env)
                response = run.command([HOST, 'select', children['B'].pid], check=True, timeout=5)
                if response.stdout.strip() != 'selected_test_pid': raise RuntimeError('test PID not acknowledged')
                for child in children.values(): child.stdin.write(b'go\n'); child.stdin.flush()
                for label, child in children.items():
                    stdout, stderr = child.communicate(timeout=4)
                    observations.append({'iteration': iteration, 'protocol': protocol, 'process': label, 'pid': child.pid, 'returncode': child.returncode, 'probe': json.loads(stdout), 'stderr': stderr.decode()})
                response = run.command([HOST, 'events'], check=True, timeout=5)
                events.append({'iteration': iteration, 'protocol': protocol, 'events': json.loads(response.stdout)})
            run.save('observations.json', observations); run.save('provider-events.json', events)
            if iteration % 20 == 19: print(f'completed {iteration + 1}/{count} pairs for each protocol', flush=True)
        time.sleep(0.5)
    finally:
        for child in children.values():
            if child.poll() is None: child.kill(); child.communicate(timeout=3)
        stopped.set()
        for thread in threads: thread.join(timeout=2)
        tcp.close(); udp.close()
        run.save('receiver.json', {'observations': received, 'errors': receiver_errors})
        run.save('observations.json', observations); run.save('provider-events.json', events)
        cleanup = run.command([HOST, 'remove'], timeout=10)
        run.save('cleanup.json', {'probe_processes_exited': all(c.poll() is not None for c in children.values()), 'receivers_exited': all(not t.is_alive() for t in threads), 'configuration_absent': cleanup.returncode == 0 or cleanup.stdout.strip() == 'no_configuration', 'extension_remains_installed': True})
    received_tokens = [item['payload'] for item in received]
    expected = {f'{i}-{p}-A' for i in range(count) for p in ['tcp', 'udp']}
    expected_decisions = {o['pid']: ('decline_direct' if o['process'] == 'A' else 'accept_and_close') for o in observations}
    flow_events = [e for sample in events for e in sample['events']]
    correlation = len(flow_events) == len(observations) and {e['pid'] for e in flow_events} == set(expected_decisions) and all(e['token'] and e['decision'] == expected_decisions.get(e['pid']) for e in flow_events)
    return {'scope': 'F01 known-PID A/B loopback TCP and UDP echo, fresh processes each pair; no VPN/lineage claim', 'pairs_per_protocol': count, 'receiver_count': len(received_tokens), 'expected_receiver_count': len(expected), 'receiver_errors': receiver_errors, 'missing_A': sorted(expected - set(received_tokens)), 'unexpected_or_B': sorted(set(received_tokens) - expected), 'duplicate_receive_count': len(received_tokens) - len(set(received_tokens)), 'flow_event_count': len(flow_events), 'pid_decision_correlation': correlation, 'client_A_failures': sum(o['process'] == 'A' and o['returncode'] != 0 for o in observations), 'client_B_successes': sum(o['process'] == 'B' and o['returncode'] == 0 for o in observations)}


def execute(run):
    mode = os.environ.get('INVPN_F01_MODE', 'external_tcp')
    run.manifest['f01_mode'] = mode
    # Retain machine-side comparison conditions without exporting identifiers.
    run.command(['scutil', '--nc', 'list'], name='network-services.json')
    run.command(['systemextensionsctl', 'list'], name='system-extensions.json')
    return {'loopback': loopback, 'external_tcp': external_tcp, 'external_sockets': external_sockets, 'client_matrix': client_matrix, 'loopback_confirm': loopback_confirm}[mode](run)
