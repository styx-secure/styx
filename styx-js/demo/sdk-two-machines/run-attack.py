#!/usr/bin/env python3
"""Public-key-only coordination. No group key is sent to the remote tester."""
import argparse,json,pathlib,subprocess,queue,threading,time,urllib.request,urllib.parse
p=argparse.ArgumentParser();p.add_argument('--out',required=True);a=p.parse_args()
root=pathlib.Path(__file__).parent
out=pathlib.Path(a.out).resolve();out.mkdir(parents=True,exist_ok=True)
base=root if (root/'attack-host.py').exists() else root/'styx-nov/styx-js/demo/sdk-two-machines'
remote='/home/mverde/reviews/sdk-demo-2026-11'
remoteout=remote+'/'+out.name
worker='https://styx-sdk-mallory-nov.cirrosi.workers.dev'
def api(path,method='GET'):
    req=urllib.request.Request(worker+path,method=method,headers={'User-Agent':'Mozilla/5.0'})
    with urllib.request.urlopen(req,timeout=65) as r:return json.load(r)
def save(name,data):(out/name).write_text(json.dumps(data,indent=2))
req=urllib.request.Request('https://api.ipify.org',headers={'User-Agent':'Mozilla/5.0'})
localip=urllib.request.urlopen(req,timeout=20).read().strip()
remoteip=subprocess.check_output(['ssh','ai395',"curl -sS --max-time 20 https://api.ipify.org"],timeout=25).strip()
save('networks.json',{'distinctPublicEgress':localip!=remoteip})
if not localip or not remoteip or localip==remoteip:raise RuntimeError('two-network check failed')
commands={'inviter':['ssh','ai395',f'DEMO_NODE=$HOME/.nvm/versions/node/v24.18.0/bin/node nice -n 19 ionice -c 3 python3 {remote}/styx/styx-js/demo/sdk-two-machines/attack-host.py --role inviter --out {remoteout}'], 'invitee':['python3',str(base/'attack-host.py'),'--role','invitee','--out',str(out)]}
procs={};q=queue.Queue();keys={};stop=threading.Event();poller=None

def reader(role,proc):
    with open(out/('controller-'+role+'.log'),'w') as f:
        for line in proc.stdout:f.write(line);f.flush();q.put((role,line))
    q.put((role,None))
def polling():
    while not stop.is_set():
        try:
            api('/tick')
            save('mallory-log.json',api('/log'))
        except Exception as e:
            with open(out/'poll-errors.log','a') as f:f.write(type(e).__name__+': '+str(e)+'\n')
        stop.wait(3)
try:
    save('worker-health.json',api('/health'))
    for role,cmd in commands.items():
        proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        procs[role]=proc;threading.Thread(target=reader,args=(role,proc),daemon=True).start()
    end=time.monotonic()+330;started=False;ended=set()
    while len(ended)<2:
        if time.monotonic()>end:raise RuntimeError('controller timeout')
        try:role,line=q.get(timeout=1)
        except queue.Empty:continue
        if line is None:
            ended.add(role)
            if procs[role].wait(timeout=10) != 0: raise RuntimeError(role+' process failed; see controller log')
            continue
        try:e=json.loads(line)
        except ValueError: print(role,line.strip(),flush=True);continue
        if e.get('phase')=='host-public-key':
            keys[role]=e['publicKey']
            if len(keys)==2:
                params=urllib.parse.urlencode({'p':keys['invitee'],'g':keys['inviter'],'r':'wss://relay.nostr.net,wss://relay.primal.net,wss://offchain.pub','skip':0,'silence':6000,'ttl':300,'label':out.name})
                save('mallory-arm.json',api('/arm?'+params,'POST'))
                poller=threading.Thread(target=polling,daemon=True);poller.start()
                procs['invitee'].stdin.write(json.dumps({'peer':keys['inviter']})+'\n');procs['invitee'].stdin.flush()
        if e.get('phase')=='waiting-for-invite' and role=='invitee' and not started:
            procs['inviter'].stdin.write(json.dumps({'peer':keys['invitee']})+'\n');procs['inviter'].stdin.flush();started=True
        if e.get('phase') in ['host-public-key','mls-ready','hold-window-start','true-receipt-release','delivery-terminal','failure','result','host-result']:print(json.dumps(e),flush=True)
    codes={role:proc.wait(timeout=20) for role,proc in procs.items()}
    stop.set()
    if poller:poller.join(timeout=70)
    save('mallory-log.json',api('/log'))
    subprocess.run(['scp','-q',*[f'ai395:{remoteout}/{n}' for n in ['inviter.log','inviter-result.json','host-inviter.json','net-inviter.jsonl']],str(out)+'/'],check=True)
    results=[json.loads((out/(r+'-result.json')).read_text()) for r in ['inviter','invitee']]
    summary={'processExit':codes,'ok':all(r.get('ok') for r in results) and all(c==0 for c in codes.values()),'equalMlsFingerprint':results[0].get('groupFingerprint')==results[1].get('groupFingerprint')}
    save('summary.json',summary);print(json.dumps(summary),flush=True)
finally:
    stop.set()
    for proc in procs.values():
        if proc.poll() is None:proc.terminate()
    try:
        save('mallory-disarm.json',api('/disarm','POST'))
        save('worker-health-final.json',api('/health'))
    except Exception as e:print('disarm check failed:',e,flush=True)
