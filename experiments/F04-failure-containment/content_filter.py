"""Independent content-filter candidate, constrained to one local test endpoint."""
import importlib.util
import json
import select
import subprocess
import time


def execute(run):
    spec=importlib.util.spec_from_file_location('multi',run.root/'experiments/F07-multiple-vpns/run.py')
    multi=importlib.util.module_from_spec(spec);spec.loader.exec_module(multi)
    f=multi.load(run); normal=vpn_receiver=vpn=None; children={}; observations=[]; events=[]
    def sample(phase):
        before=[sum(bool(e.get('request')) for e in r.events) for r in [normal,vpn_receiver]]
        clients={}
        for label,child in children.items():
            child.stdin.write(b't');child.stdin.flush()
            if not select.select([child.stdout],[],[],6)[0]:raise TimeoutError('client response absent')
            clients[label]=json.loads(child.stdout.readline())
        time.sleep(.1)
        observations.append({'phase':phase,'clients':clients,'normal_received':sum(bool(e.get('request')) for e in normal.events)-before[0],'vpn_received':sum(bool(e.get('request')) for e in vpn_receiver.events)-before[1]})
        run.save('observations.json',observations)
        return clients
    def guard_pids():
        result=subprocess.run(['ps','-axo','pid=,comm='],capture_output=True,text=True,timeout=5)
        return [int(line.split()[0]) for line in result.stdout.splitlines() if line.strip().endswith('/jp.diverge.invpn.feasibility.guard')]
    try:
        normal=multi.Receiver('normal','192.0.2.1');vpn_receiver=multi.Receiver('vpn1','192.0.2.11')
        vpn=f.LocalVPN(run,'guard-vpn',vpn_receiver.tcp.getsockname()[1],vpn_receiver.udp.getsockname()[1]);vpn.bridge.test_destination='10.77.0.99'
        port=normal.tcp.getsockname()[1]
        binary=run.compile_c(run.root/'test-support/probes/https_probe.c','guard-http',['-lcurl'])
        for label in ['A','B']:
            children[label]=subprocess.Popen([str(binary),f'http://127.0.0.1:{port}/guard'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=run.env)
        controls=sample('before_all')
        if not all(x['http_status']==200 for x in controls.values()):raise RuntimeError('direct baseline failed')
        multi.start(run,'127.0.0.1',port,False);multi.route(run,children['B'].pid,vpn.bridge)
        sample('transparent_only')
        run.command([multi.HOST,'guard-start','127.0.0.1',port,children['B'].pid],timeout=180,check=True)
        time.sleep(1);sample('transparent_plus_filter')
        events=json.loads(run.command([multi.HOST,'events'],timeout=8,check=True).stdout)
        run.command([multi.HOST,'remove'],timeout=15,check=True);time.sleep(1)
        for i in range(3):sample(f'filter_only_{i}')
        # Reconfigure this filter with a timed abort; retain exact process evidence.
        run.command([multi.HOST,'guard-remove'],timeout=15,check=True);time.sleep(.5)
        run.command([multi.HOST,'guard-start','127.0.0.1',port,children['B'].pid,'4'],timeout=180,check=True)
        time.sleep(.5);pids=guard_pids();run.save('guard-before-crash.json',{'pids':pids})
        sample('filter_before_abort');time.sleep(4)
        after=guard_pids();run.save('guard-after-crash.json',{'pids':after,'original_disappeared':bool(pids) and not bool(set(pids)&set(after))})
        if not pids or set(pids)&set(after):raise RuntimeError('Filter crash not confirmed; no claim of post-crash enforcement')
        for i in range(10):sample(f'filter_after_abort_{i}');time.sleep(.1)
        return {'scope':'separate content-filter process, one local TCP endpoint and known B PID','observations':observations}
    finally:
        for child in children.values():
            if child.poll() is None:child.kill();child.communicate(timeout=3)
        run.save('observations.json',observations);run.save('provider-events.json',events)
        if normal:run.save('normal-receiver.json',normal.events)
        if vpn_receiver:run.save('vpn-receiver.json',vpn_receiver.events)
        proxy_removed=run.command([multi.HOST,'remove'],timeout=15)
        filter_removed=run.command([multi.HOST,'guard-remove'],timeout=15)
        if vpn:vpn.close()
        for r in [normal,vpn_receiver]:
            if r:r.close()
        run.save('cleanup.json',{'proxy_configuration_absent':proxy_removed.returncode==0 or proxy_removed.stdout.strip()=='no_configuration','filter_configuration_removed':filter_removed.returncode==0,'clients_exited':all(c.poll() is not None for c in children.values()),'backend_exited':vpn is None or (vpn.client.process.poll() is not None and vpn.server.process.poll() is not None)})
