"""Probe OS session ID as a candidate, including its setsid counterexample."""
import importlib.util
import json
import subprocess
import time


def execute(run):
    spec=importlib.util.spec_from_file_location('multi',run.root/'experiments/F07-multiple-vpns/run.py')
    multi=importlib.util.module_from_spec(spec);spec.loader.exec_module(multi)
    f=multi.load(run); receiver=vpn=None; child=None; observations=[]; events=[]
    try:
        receiver=multi.Receiver('vpn1','192.0.2.11')
        vpn=f.LocalVPN(run,'lineage',receiver.tcp.getsockname()[1],receiver.udp.getsockname()[1])
        binary=run.compile_c(run.root/'experiments/F02-process-lineage/Sources/session.c','session-probe')
        multi.start(run,'10.77.0.99',18080,False)
        for mode,count in [('burst',100),('exec',100),('reparent',1),('setsid',1)]:
            child=subprocess.Popen(['/bin/zsh','-f','-c','read -r gate; exec "$@"','probe',str(binary),mode,'18080',str(count)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=run.env,start_new_session=True)
            path=run.path/f'route-{child.pid}.private.json'
            run.save(path.name,{'pid':child.pid,'port':vpn.bridge.port,'secret':vpn.bridge.secret,'selection':'session'})
            response=run.command([multi.HOST,'route',path],timeout=10,check=True)
            if response.stdout.strip()!='route_registered':raise RuntimeError('session registration failed')
            stdout,stderr=child.communicate(b'go\n',timeout=100)
            reports=[json.loads(line) for line in stdout.decode().splitlines()]
            observations.append({'mode':mode,'root_pid':child.pid,'returncode':child.returncode,'requested':count,'child_results':reports,'stderr':stderr.decode()})
            run.save('observations.json',observations)
            if mode=='burst' and not any(r['reply'] for r in reports):break
        events=json.loads(run.command([multi.HOST,'events'],timeout=10,check=True).stdout)
        return {'scope':'session ID heuristic, automatic child-flow selection; not Endpoint Security','observations':observations,'receiver':receiver.events}
    finally:
        if child is not None and child.poll() is None:child.kill();child.communicate(timeout=3)
        run.save('observations.json',observations);run.save('provider-events.json',events)
        if receiver:run.save('receivers.json',receiver.events)
        removed=run.command([multi.HOST,'remove'],timeout=15)
        if vpn:vpn.close()
        if receiver:receiver.close()
        # Any orphan should have ended before closing its inherited stdout pipe.
        run.save('cleanup.json',{'configuration_absent':removed.returncode==0 or removed.stdout.strip()=='no_configuration','root_exited':child is None or child.poll() is not None,'owned_backend_exited':vpn is None or (vpn.client.process.poll() is not None and vpn.server.process.poll() is not None)})
