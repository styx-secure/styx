#!/usr/bin/env python3
"""Real two-host offline-recipient observations; never rewrite SDK frames."""
import argparse, json, pathlib, queue, socket, subprocess, sys, threading, time, urllib.request
p=argparse.ArgumentParser()
p.add_argument('--out',required=True)
p.add_argument('--variant',choices=['before-deadline','after-deadline'],required=True)
p.add_argument('--relay-mode',choices=['public','local'],default='public')
a=p.parse_args()
assert socket.gethostname()=='MVLINNA'
base=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(a.out).resolve(); out.mkdir(parents=True,exist_ok=False)
q=queue.Queue(); events=[]; consumed=set(); hosts={}; tunnel=None
summary={'ok':False,'variant':a.variant,'relayMode':a.relay_mode,'deadlineMs':90000}
relays={r:'wss://relay.nostr.net,wss://relay.primal.net,wss://offchain.pub' for r in ['inviter','invitee']}
def reader(role,proc):
    for line in proc.stdout:
        try:e=json.loads(line)
        except ValueError:e={'phase':'controller-stderr','message':line.strip()}
        q.put({**e,'role':role,'observedNs':time.monotonic_ns()})
    q.put({'role':role,'phase':'controller-eof','observedNs':time.monotonic_ns()})
def record(e,strict=True):
    events.append(e)
    with open(out/'controller.jsonl','a') as f:f.write(json.dumps(e)+'\n')
    if e['phase'] not in ['wire','delivery','discard']:print(json.dumps(e),flush=True)
    if strict and e['phase'] in ['failure','host-failure','guard-failure']:raise RuntimeError(str(e))
def wait(role,phase,predicate=lambda e:True,timeout=110):
    end=time.monotonic()+timeout
    while True:
        for i,e in enumerate(events):
            if i not in consumed and e['role']==role and e['phase']==phase and predicate(e):consumed.add(i);return e
        if time.monotonic()>end:raise RuntimeError('timeout '+str((role,phase)))
        try:record(q.get(timeout=0.3))
        except queue.Empty:pass
def pump(seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:record(q.get(timeout=min(0.3,max(0.01,end-time.monotonic()))))
        except queue.Empty:pass
def send(role,**cmd):
    stream=hosts[role].stdin; assert stream is not None
    stream.write(json.dumps(cmd)+'\n'); stream.flush()
def launch(role):
    send(role,op='launch',peer=keys['inviter' if role=='invitee' else 'invitee'],relays=relays[role])
    return wait(role,'started')
def stop(role):
    send(role,op='stop');wait(role,'stopped');assert wait(role,'host-exit')['exit']==0
def snapshot(role):
    send(role,op='snapshot');return wait(role,'snapshot')
def message(id):
    send('inviter',op='send',id=id)
    e=wait('inviter','terminal',lambda e:e['id']==id)
    assert e['state']=='RECIPIENT_RECEIPT_RECEIVED',e
try:
    if a.relay_mode=='public':
        probe="import urllib.request; print(urllib.request.urlopen('https://checkip.amazonaws.com',timeout=20).read().decode().strip())"
        localip=urllib.request.urlopen('https://checkip.amazonaws.com',timeout=20).read().strip()
        remoteip=subprocess.check_output(['ssh','AI395','python3 -c '+__import__('shlex').quote(probe)],timeout=30).strip()
        summary['distinctPublicEgress']=localip!=remoteip;assert summary['distinctPublicEgress']
    remote='/home/mverde/reviews/sdk-demo-2026-11/styx/styx-js/demo/sdk-two-machines/offline-host.py'
    commands={'inviter':['ssh','AI395',f'DEMO_NODE=$HOME/.nvm/versions/node/v24.18.0/bin/node nice -n 19 ionice -c 3 python3 {remote} --role inviter --out {out} --lock'+(' --local-relays' if a.relay_mode=='local' else '')],
              'invitee':['nice','-n','19','ionice','-c','3','python3',str(base/'offline-host.py'),'--role','invitee','--out',str(out)]}
    for role,cmd in commands.items():
        proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1);hosts[role]=proc
        threading.Thread(target=reader,args=(role,proc),daemon=True).start()
    if a.relay_mode=='local':
        urls=wait('inviter','local-relays')['urls'];relays['inviter']=','.join(urls)
        ports=[]
        for _ in urls:
            with socket.socket() as s:s.bind(('127.0.0.1',0));ports.append(s.getsockname()[1])
        cmd=['ssh','-N','-o','ExitOnForwardFailure=yes']
        for port,url in zip(ports,urls):cmd.extend(['-L',f'127.0.0.1:{port}:127.0.0.1:{url.rsplit(":",1)[1]}'])
        cmd.append('AI395')
        tunnel=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=open(out/'tunnel.log','w'))
        relays['invitee']=','.join('ws://127.0.0.1:'+str(port) for port in ports)
        pump(2);assert tunnel.poll() is None
    summary['relays']=relays
    keys={r:wait(r,'public-key')['publicKey'] for r in hosts}
    for r in hosts:launch(r)
    send('invitee',op='pair');wait('invitee','waiting-for-invite');send('inviter',op='pair')
    paired=[wait(r,'paired') for r in hosts];fingerprint=paired[0]['fingerprint'];assert all(e['fingerprint']==fingerprint for e in paired)
    for id in ['m1','m2']:message(id)
    stop('invitee'); stopped_ns=time.monotonic_ns()
    record({'role':'controller','phase':'offline-start','observedNs':stopped_ns})
    for id in ['m3','m4']:send('inviter',op='send',id=id)
    admissions={id:wait('inviter','sent',lambda e,id=id:e['id']==id) for id in ['m3','m4']}
    # Both sends are pending concurrently; wait by real monotonic elapsed time.
    duration=65 if a.variant=='before-deadline' else 105
    pump(max(0,duration-(time.monotonic_ns()-stopped_ns)/1e9))
    before=snapshot('inviter');summary['beforeRestartDeliveries']=before['deliveries']
    assert not any(e['phase']=='message' and e.get('id') in ['m3','m4'] for e in events)
    restart_ns=time.monotonic_ns()
    record({'role':'controller','phase':'restart-request','observedNs':restart_ns,'offlineSeconds':(restart_ns-stopped_ns)/1e9})
    restored=launch('invitee');assert restored['self']==keys['invitee'] and restored['fingerprint']==fingerprint
    summary['offlineSeconds']=(restart_ns-stopped_ns)/1e9
    pump(32)
    snapshots={r:snapshot(r) for r in hosts}
    for r in hosts:stop(r)
    for r in hosts:send(r,op='finish')
    cleanups={r:wait(r,'host-cleanup') for r in hosts};codes={r:proc.wait(timeout=30) for r,proc in hosts.items()}
    pump(0.5)
    for c in cleanups.values():
        assert c['stateRemoved'] and c['stateDirectoryMode']=='0o700' and set(c['fileModes'].values())=={'0o600'} and not c['errors']
        if c['hostname']=='AI395':assert c['availableMinimum']>=15_000_000_000 and c['llamaSwapPidBefore']==c['llamaSwapPidAfter']
    assert all(c==0 for c in codes.values())
    assert all(e['fingerprint']==fingerprint for e in snapshots.values())
    summary.update(ok=True,meaning='measurement completed, not an SDK reliability guarantee',admissions=admissions,finalDeliveries=snapshots['inviter']['deliveries'],cleanups=cleanups,processExit=codes)
except Exception as e:
    summary['error']=str(e)
finally:
    for r,proc in hosts.items():
        if proc.poll() is None:
            try:send(r,op='finish')
            except (OSError,BrokenPipeError):pass
    for proc in hosts.values():
        if proc.poll() is None:
            try:proc.wait(timeout=20)
            except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10)
    while not q.empty():record(q.get_nowait(),strict=False)
    if tunnel:tunnel.terminate();tunnel.wait(timeout=10)
    (out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary),flush=True)
if not summary['ok']:sys.exit(1)
