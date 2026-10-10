import json
import subprocess
import time
import uuid

HOST = '/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility'


def execute(run):
    binary = run.compile_c(run.root / 'test-support/probes/dns_probe.c', 'dns-probe')
    children, observations, events = {}, [], []
    try:
        run.command([HOST, 'start', 443, 0, '1.1.1.1', 'dns'], check=True, timeout=60)
        for _ in range(30):
            response = run.command([HOST, 'status'], timeout=5)
            if response.returncode == 0 and response.stdout.startswith('{') and json.loads(response.stdout).get('ready'): break
            time.sleep(0.2)
        else: raise RuntimeError('provider not ready')
        # An ordinary TCP pair is tested separately in F01. Here use fresh names
        # in a dedicated domain; no global DNS server or cache changes.
        for mode in ['getaddrinfo', 'dig']:
            names = {label: f'{uuid.uuid4().hex}.invpn-feasibility.example.com' for label in ['A', 'B']}
            children = {}
            for label in ['A', 'B']:
                command = [str(binary), names[label]] if mode == 'getaddrinfo' else ['/usr/bin/dig', '+tries=1', '+time=2', names[label], 'A']
                children[label] = subprocess.Popen(['/bin/zsh', '-f', '-c', 'read -r gate; exec "$@"', 'probe-shell', *command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run.env)
            selected = run.command([HOST, 'select', children['B'].pid], check=True, timeout=5)
            if selected.stdout.strip() != 'selected_test_pid': raise RuntimeError('PID not selected')
            for child in children.values(): child.stdin.write(b'go\n'); child.stdin.flush()
            for label, child in children.items():
                timed_out = False
                try: stdout, stderr = child.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    child.kill(); stdout, stderr = child.communicate(timeout=3); timed_out = True
                observations.append({'mode': mode, 'process': label, 'pid': child.pid, 'query': names[label], 'returncode': child.returncode, 'timed_out': timed_out, 'stdout': stdout.decode(), 'stderr': stderr.decode()})
            time.sleep(0.2)
            response = run.command([HOST, 'events'], check=True, timeout=5)
            events.append({'mode': mode, 'events': json.loads(response.stdout)})
            run.save('observations.json', observations); run.save('provider-events.json', events)
        pids = sorted({e['pid'] for sample in events for e in sample['events'] if e.get('pid')})
        if pids: run.command(['ps', '-p', ','.join(map(str, pids)), '-o', 'pid=,ppid=,comm='], name='source-processes.json')
    finally:
        for child in children.values():
            if child.poll() is None: child.kill(); child.communicate(timeout=3)
        run.save('observations.json', observations); run.save('provider-events.json', events)
        cleanup = run.command([HOST, 'remove'], timeout=10)
        run.save('cleanup.json', {'children_exited': all(c.poll() is not None for c in children.values()), 'configuration_absent': cleanup.returncode == 0 or cleanup.stdout.strip() == 'no_configuration', 'system_dns_changed': False})
    return {'scope': 'F03 exploratory source attribution for fresh names, standard getaddrinfo versus explicit dig; domain-based transparent rule only', 'observations': observations, 'provider_events': events, 'unverified': ['per-VPN resolver selection', 'cache isolation', 'shared-name concurrency', 'URLSession', 'DNS proxy candidate', 'VPN DNS path']}
