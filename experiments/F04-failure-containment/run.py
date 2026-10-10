import json
import socket
import time


PROFILE = '(version 1)(allow default)(deny network*)'


def sandbox(run):
    binary = run.compile_c(run.root / 'test-support/probes/socket_probe.c', 'socket-probe')
    observations, received = [], []
    for family, host in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
        for protocol, kind in [('tcp', socket.SOCK_STREAM), ('udp', socket.SOCK_DGRAM)]:
            with socket.socket(family, kind) as server:
                server.bind((host, 0))
                port = server.getsockname()[1]
                server.settimeout(0.15)
                if protocol == 'tcp': server.listen()
                for condition in ['baseline', 'deny_new', 'deny_inherited', 'deny_fork_exec', 'after_baseline']:
                    if condition == 'deny_fork_exec' and protocol == 'udp': continue
                    token = f'{family}-{protocol}-{condition}'
                    connection, inherited = None, None
                    try:
                        args = [binary, protocol, host, port, token]
                        if condition == 'deny_inherited':
                            inherited = socket.socket(family, kind)
                            inherited.connect((host, port))
                            if protocol == 'tcp': connection, _ = server.accept()
                            args = [binary, 'inherited', host, inherited.fileno(), token]
                        if condition == 'deny_fork_exec': args[1] = 'fork-tcp'
                        if condition.startswith('deny'):
                            args = ['/usr/bin/sandbox-exec', '-p', PROFILE, *args]
                        result = run.command(args, timeout=3, pass_fds=() if inherited is None else (inherited.fileno(),))
                        payload, peer = None, None
                        try:
                            if protocol == 'tcp':
                                if connection is None: connection, peer = server.accept()
                                connection.settimeout(0.15)
                                payload = connection.recv(1024).decode()
                            else:
                                data, peer = server.recvfrom(1024)
                                payload = data.decode()
                        except socket.timeout:
                            pass
                        delivered = payload == token
                        if payload is not None: received.append({'time_ns': time.monotonic_ns(), 'token': payload, 'peer': peer})
                        observations.append({'family': family.name, 'protocol': protocol, 'condition': condition, 'returncode': result.returncode, 'probe': json.loads(result.stdout) if result.stdout.strip().startswith('{') else None, 'stderr': result.stderr, 'received_expected_payload': delivered})
                    finally:
                        if connection is not None: connection.close()
                        if inherited is not None: inherited.close()
    run.save('receiver.json', received)
    run.save('observations.json', observations)
    run.save('cleanup.json', {'all_probe_processes_waited': True, 'all_sockets_closed': True, 'persistent_system_changes': False})
    controls = all(o['received_expected_payload'] for o in observations if o['condition'] in ['baseline', 'after_baseline'])
    inherited_leaks = [o for o in observations if o['condition'] == 'deny_inherited' and o['received_expected_payload']]
    return {'scope': 'F04 exploratory sandbox candidate, local IPv4/IPv6 TCP/UDP only; not a provider-crash test', 'profile': PROFILE, 'controls_received': controls, 'observations': observations, 'inherited_delivery_count': len(inherited_leaks), 'unverified': ['external routes', 'transparent forwarding compatibility', 'provider or guard crash', '20 repeats per failure/stage', 'standard DNS', 'raw sockets']}


def execute(run):
    import os
    if os.environ.get('INVPN_F04_MODE') in {'provider_crash', 'content_filter'}:
        import importlib.util
        path = run.root / 'experiments/F04-failure-containment' / (os.environ['INVPN_F04_MODE'] + '.py')
        spec = importlib.util.spec_from_file_location('provider_crash', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module.execute(run)
    return sandbox(run)
