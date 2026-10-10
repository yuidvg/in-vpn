import json
import socket
import subprocess
import threading
import time


def execute(run):
    import os, importlib.util
    if os.environ.get("INVPN_F02_MODE") == "session":
        spec = importlib.util.spec_from_file_location("session", run.root / "experiments/F02-process-lineage/session.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module.execute(run)

    binary = run.compile_c(run.root / 'experiments/F02-process-lineage/Sources/lineage.c', 'lineage')
    observations = []
    for mode, count in [('burst', 1000), ('reparent', 1)]:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(('127.0.0.1', 0))
        receiver.settimeout(0.1)
        received, snapshots = [], []
        stop = threading.Event()

        def collect():
            while not stop.is_set():
                try:
                    data, peer = receiver.recvfrom(2048)
                    received.append({'time_ns': time.monotonic_ns(), 'peer': peer, 'payload': json.loads(data)})
                except socket.timeout:
                    continue

        def snapshot():
            while not stop.is_set():
                before = time.monotonic_ns()
                result = subprocess.run(['/bin/ps', '-A', '-o', 'pid=,ppid='], capture_output=True, text=True)
                entries = [list(map(int, line.split())) for line in result.stdout.splitlines()]
                snapshots.append({'start_ns': before, 'end_ns': time.monotonic_ns(), 'entries': entries, 'returncode': result.returncode})
                stop.wait(0.01)

        threads = [threading.Thread(target=collect), threading.Thread(target=snapshot)]
        for thread in threads: thread.start()
        try:
            result = run.command([binary, mode, receiver.getsockname()[1], count], check=True, timeout=30)
            time.sleep(0.2)
        finally:
            stop.set()
            for thread in threads: thread.join(timeout=2)
            receiver.close()
        launched = [json.loads(line) for line in result.stdout.splitlines()]
        child_ids = {entry['child'] for entry in launched}
        observed_ids = {pid for snapshot in snapshots for pid, _ in snapshot['entries']} & child_ids
        # Do not persist unrelated process data collected by ps.
        selected_ids = child_ids | {entry.get('parent', 0) for entry in launched}
        for snapshot in snapshots:
            snapshot['entries'] = [entry for entry in snapshot['entries'] if entry[0] in selected_ids]
        run.save(f'{mode}/launcher.json', launched)
        run.save(f'{mode}/receiver.json', received)
        run.save(f'{mode}/snapshots.json', snapshots)
        valid_received = {entry['payload']['pid'] for entry in received} & child_ids
        observations.append({'mode': mode, 'launched': len(child_ids), 'received_from_distinct_children': len(valid_received), 'sampled_children': len(observed_ids), 'sent_but_never_sampled': len(valid_received - observed_ids), 'snapshot_count': len(snapshots), 'ps_failures': sum(item['returncode'] != 0 for item in snapshots), 'ppid_at_send': sorted({item['payload']['ppid_at_send'] for item in received}) if mode == 'reparent' else None})
        if mode == 'reparent':
            # Wait until launchd has reaped the exited orphan. No PID-based killing.
            remaining = child_ids.copy()
            for _ in range(40):
                remaining = {pid for pid in remaining if subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'pid='], capture_output=True).returncode == 0}
                if not remaining: break
                time.sleep(0.05)
            if remaining: raise RuntimeError('orphan process exit not confirmed')
    run.save('cleanup.json', {'all_probe_processes_exited': True, 'receiver_sockets_closed': True, 'persistent_system_changes': False})
    return {'scope': 'F02 snapshot-only counterexamples on loopback; no NE flow attribution', 'observations': observations, 'conclusion': 'derive from missing children and reparent observations; ES/event-based candidates remain untested', 'unverified': ['exec/spawn integration', 'PID generation/reuse', 'NE first-flow ordering', '10,000-run candidate confirmation']}
