#!/usr/bin/env python3
"""Run loopback on AI395, or coordinate AI395 inviter + MVLINNA invitee."""
import argparse, fcntl, json, os, pathlib, queue, socket, subprocess, sys, threading, time, urllib.request
p=argparse.ArgumentParser(); p.add_argument('--out',required=True); p.add_argument('--mode',choices=['loopback','public'],required=True); p.add_argument('--remote-root',default='/home/mverde/reviews/sdk-demo-2026-11/styx'); a=p.parse_args()
base=pathlib.Path(__file__).resolve().parent; out=pathlib.Path(a.out).resolve(); out.mkdir(parents=True,exist_ok=True)
node=os.environ.get('DEMO_NODE','node'); hosts={}; fixture=None; lock=None; q=queue.Queue(); events=[]; cursors={}; summary={'ok':False,'mode':a.mode}
def reader(role,proc):
    for line in proc.stdout:
        try: e=json.loads(line)
        except ValueError: e={'phase':'controller-stderr','message':line.strip()}
        e['role']=role; q.put(e)
    q.put({'role':role,'phase':'controller-eof'})
def drain(e):
    events.append(e)
    with open(out/'controller.jsonl','a') as f:f.write(json.dumps(e)+'\n')
    if e['phase'] not in ['delivery','discard']:print(json.dumps(e),flush=True)
    if e['phase'] in ['failure','host-failure','guard-failure']:raise RuntimeError(str(e))
def wait(role,phase,timeout=100):
    key=(role,phase); start=cursors.get(key,0); end=time.monotonic()+timeout
    while True:
        for i in range(start,len(events)):
            if events[i]['role']==role and events[i]['phase']==phase:
                cursors[key]=i+1; return events[i]
        start=len(events)
        if time.monotonic()>end:raise RuntimeError('timeout '+str(key))
        try:drain(q.get(timeout=1))
        except queue.Empty:pass
def send(role,**command):
    proc=hosts[role]; proc.stdin.write(json.dumps(command)+'\n'); proc.stdin.flush()
def launch(role):
    send(role,op='launch',peer=keys['invitee' if role=='inviter' else 'inviter'],relays=relays)
    return wait(role,'started')
def stop(role):
    send(role,op='stop'); wait(role,'stopped'); e=wait(role,'host-exit'); assert e['exit']==0,e
def message(role,id):
    send(role,op='send',id=id); e=wait(role,'terminal'); assert e['id']==id and e['state']=='RECIPIENT_RECEIPT_RECEIVED',e
try:
    if a.mode=='loopback':
        assert socket.gethostname()=='AI395','loopback must run on AI395'
        lock=open('/home/mverde/reviews/styx-kanban/.ai395-test.lock','a'); fcntl.flock(lock,fcntl.LOCK_EX)
        fixture=subprocess.Popen([node,str(base/'persistent-relays.mjs')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        relays=','.join(json.loads(fixture.stdout.readline())['urls'])
        commands={r:['python3',str(base/'persistent-host.py'),'--role',r,'--out',str(out)] for r in ['inviter','invitee']}
    else:
        assert socket.gethostname()=='MVLINNA','public controller must run on MVLINNA'
        localip=urllib.request.urlopen('https://api.ipify.org',timeout=20).read().strip()
        remoteip=subprocess.check_output(['ssh','AI395','python3 -c "import urllib.request; print(urllib.request.urlopen(\'https://api.ipify.org\',timeout=20).read().decode())"'],timeout=30).strip()
        summary['distinctPublicEgress']=localip!=remoteip; assert summary['distinctPublicEgress']
        relays='wss://relay.nostr.net,wss://relay.primal.net,wss://offchain.pub'
        remote=a.remote_root+'/styx-js/demo/sdk-two-machines/persistent-host.py'; remoteout=str(out)
        commands={'inviter':['ssh','AI395',f'DEMO_NODE=$HOME/.nvm/versions/node/v24.18.0/bin/node nice -n 19 ionice -c 3 python3 {remote} --role inviter --out {remoteout} --lock'],
                  'invitee':['python3',str(base/'persistent-host.py'),'--role','invitee','--out',str(out)]}
    for r,cmd in commands.items():
        proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1); hosts[r]=proc
        threading.Thread(target=reader,args=(r,proc),daemon=True).start()
    keys={r:wait(r,'public-key')['publicKey'] for r in ['inviter','invitee']}
    for r in hosts:launch(r)
    send('invitee',op='pair');wait('invitee','waiting-for-invite');send('inviter',op='pair')
    paired=[wait(r,'paired') for r in hosts]; fingerprint=paired[0]['fingerprint']; assert all(e['fingerprint']==fingerprint for e in paired)
    for n in range(1,4):
        message('inviter','before-'+str(n));message('invitee','reply-before-'+str(n))
    for r in hosts:stop(r)
    restored={r:launch(r) for r in hosts}
    assert all(e['self']==keys[r] and e['fingerprint']==fingerprint and e['groupId'] for r,e in restored.items()),restored
    assert restored['inviter']['groupId']==restored['invitee']['groupId']
    for n in range(1,4):
        message('inviter','after-'+str(n));message('invitee','reply-after-'+str(n))
    send('inviter',op='send',id='crash-pending',crash=True)
    wait('inviter','crash-ready'); killed=wait('inviter','host-killed'); assert killed['exit']==-9,killed
    wait('inviter','host-exit'); recovered=launch('inviter')
    assert recovered['self']==keys['inviter'] and recovered['fingerprint']==fingerprint
    assert len(recovered['recovered'])==1 and recovered['recovered'][0]['applicationOutcome']=='FAILED_AFTER_RESTART_UNKNOWN_OUTCOME',recovered
    message('inviter','after-crash');message('invitee','reply-after-crash')
    snapshots={}
    for r in hosts:send(r,op='snapshot'); snapshots[r]=wait(r,'snapshot')
    for r in hosts:stop(r)
    actual={r:[e['id'] for e in snapshots[r]['inbox']] for r in hosts}
    expected={'inviter':[f'reply-{stage}-{n}' for stage in ['before','after'] for n in range(1,4)]+['reply-after-crash'],
              'invitee':[f'{stage}-{n}' for stage in ['before','after'] for n in range(1,4)]+['after-crash']}
    for r in hosts:
        assert len(actual[r])==len(set(actual[r])),actual
        assert set(actual[r])-{'crash-pending'}==set(expected[r]),actual
        assert snapshots[r]['fingerprint']==fingerprint
    # Pending may have reached the peer before SIGKILL, but is never retried.
    crash_count=actual['invitee'].count('crash-pending'); assert crash_count in [0,1]
    for r in hosts:send(r,op='finish')
    cleanups={r:wait(r,'host-cleanup') for r in hosts}
    codes={r:proc.wait(timeout=30) for r,proc in hosts.items()}
    while not q.empty():drain(q.get_nowait())
    assert all(c==0 for c in codes.values()),codes
    assert all(e['stateRemoved'] and e['stateDirectoryMode']=='0o700' and set(e['fileModes'].values())=={'0o600'} and not e['errors'] for e in cleanups.values()),cleanups
    assert all(e['llamaSwapPidBefore']==e['llamaSwapPidAfter'] and e['availableMinimum']>=15_000_000_000 for e in cleanups.values() if e['hostname']=='AI395')
    assert not any(e['phase']=='message' and e['duplicate'] for e in events)
    summary.update(ok=True,keysStable=True,groupStable=True,mlsFingerprintStable=True,cleanRestarts=2,crashSignal='SIGKILL',pendingApplicationOutcome=recovered['recovered'],pendingReceived=crash_count,recipientReceipts=sum(e['phase']=='terminal' for e in events),applicationMessages={r:len(v) for r,v in actual.items()},duplicateApplicationEvents=0,newInvitesAfterRestart=0,cleanups=cleanups,processExit=codes,relays=relays.split(','))
except Exception as e:
    summary['error']=str(e); print(json.dumps(summary),flush=True)
finally:
    for r,proc in hosts.items():
        if proc.poll() is None:
            try:send(r,op='finish')
            except (BrokenPipeError,OSError):pass
    for r,proc in hosts.items():
        if proc.poll() is None:
            try:proc.wait(timeout=20)
            except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10)
    while not q.empty():
        e=q.get_nowait(); events.append(e)
        with open(out/'controller.jsonl','a') as f:f.write(json.dumps(e)+'\n')
    if fixture:fixture.terminate();fixture.wait(timeout=10)
    if lock:lock.close()
    (out/'summary.json').write_text(json.dumps(summary,indent=2)); print(json.dumps(summary),flush=True)
if not summary['ok']:sys.exit(1)
