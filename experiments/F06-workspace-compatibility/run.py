import json
import os
import select
from pathlib import Path
import socket
import subprocess
import tempfile


def execute(run):
    binary = run.compile_c(run.root / 'test-support/probes/socket_probe.c', 'socket-probe')
    observations = []
    with tempfile.TemporaryDirectory(prefix='invpn-', dir='/tmp') as temp:
        path = str(Path(temp).resolve() / 'receiver.sock')
        deny = '(version 1)(allow default)(deny network*)'
        allow_unix = deny + f'(allow network-outbound (literal "{path}"))'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(path); server.listen(); server.settimeout(0.15)
            for condition, profile in [('baseline', None), ('deny_all_network', deny), ('allow_one_unix_socket', allow_unix)]:
                args = [binary, 'unix', path, 0, condition]
                if profile: args = ['/usr/bin/sandbox-exec', '-p', profile, *args]
                result = run.command(args, timeout=5)
                payload = None
                try:
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(1)
                        payload = connection.recv(1024).decode()
                except socket.timeout: pass
                observations.append({'case': condition, 'returncode': result.returncode, 'received': payload == condition, 'probe': json.loads(result.stdout) if result.stdout.startswith('{') else None})
        with socket.socket() as ip_receiver:
            ip_receiver.bind(('127.0.0.1', 0)); ip_receiver.listen(); ip_receiver.settimeout(0.15)
            result = run.command(['/usr/bin/sandbox-exec', '-p', allow_unix, binary, 'tcp', '127.0.0.1', ip_receiver.getsockname()[1], 'must-block'], timeout=5)
            accepted = False
            try:
                connection, _ = ip_receiver.accept()
                connection.close(); accepted = True
            except socket.timeout: pass
            observations.append({'case': 'unix_exception_does_not_open_new_tcp', 'returncode': result.returncode, 'accepted': accepted})
        marker = 'space and 日本語 * $ literal'
        fixture = run.path / 'workspace-probe.txt'
        shell = '''test "$PWD" = "$1" || exit 21
test "$INV_F06_ENV" = "synthetic-value" || exit 22
print -rn -- "$2" > "$3"
test "$(/bin/cat "$3")" = "$2" || exit 23
print -r -- "$2" | /usr/bin/wc -l
command -v python3
python3 -c 'import os; print("uid=" + str(os.getuid()))'
'''
        result = run.command(['/usr/bin/sandbox-exec', '-p', allow_unix, '/usr/bin/env', 'INV_F06_ENV=synthetic-value', '/bin/zsh', '-f', '-c', shell, 'probe', str(run.root), marker, fixture], cwd=run.root, timeout=5)
        observations.append({'case': 'cwd_env_args_file_pipe_system_shell_nix_python', 'returncode': result.returncode, 'file_content_matches': fixture.read_text() == marker if fixture.exists() else False, 'stdout': result.stdout, 'stderr': result.stderr, 'expected_uid': os.getuid()})
        master, slave = os.openpty()
        try:
            proc = subprocess.Popen(['/usr/bin/sandbox-exec', '-p', allow_unix, '/bin/zsh', '-f', '-c', '[[ -t 0 && -t 1 ]] && print tty-ok'], stdin=slave, stdout=slave, stderr=slave, env=run.env)
            proc.wait(timeout=5)
            readable, _, _ = select.select([master], [], [], 2)
            observations.append({'case': 'inherited_tty_descriptors', 'returncode': proc.returncode, 'output': os.read(master, 1024).decode().strip() if readable else None})
        finally:
            os.close(master); os.close(slave)
    run.save('cleanup.json', {'all_probe_processes_waited': True, 'temp_unix_socket_removed': True, 'persistent_system_changes': False})
    return {'scope': 'F06 partial workspace checks with exploratory sandbox only', 'observations': observations, 'unverified': ['interactive job control/signals', 'all developer tools', 'IPC delegated egress', 'transparent VPN with protection', 'production launcher']}
