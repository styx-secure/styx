#!/usr/bin/env python3
"""Run on MVLINNA after deploying identical demo code on AI395.
Only public peer keys coordinate the protocol; copied results are evidence only.
"""
import argparse, json, pathlib, subprocess, sys, os, queue, threading, time, urllib.request
p=argparse.ArgumentParser(); p.add_argument('--out',required=True); p.add_argument('--remote-root',default='/home/mverde/reviews/sdk-demo-2026-11'); a=p.parse_args()
out=pathlib.Path(a.out).resolve(); out.mkdir(parents=True,exist_ok=True)
base=pathlib.Path(__file__).resolve().parent
remote=a.remote_root+'/styx/styx-js/demo/sdk-two-machines'
remoteout=a.remote_root+'/'+out.name
# Verify separate egress networks without retaining either IP address.
localip=urllib.request.urlopen('https://api.ipify.org',timeout=20).read().strip()
remoteip=subprocess.check_output(['ssh','ai395','python3 -c "import urllib.request; print(urllib.request.urlopen(\'https://api.ipify.org\',timeout=20).read().decode())"'],timeout=30).strip()
networks={'distinctPublicEgress':localip!=remoteip}
(out/'networks.json').write_text(json.dumps(networks,indent=2))
if not networks['distinctPublicEgress']: raise RuntimeError('same public egress: two-network criterion not met')
cmd=['ssh','ai395',f'DEMO_NODE=$HOME/.nvm/versions/node/v24.18.0/bin/node nice -n 19 ionice -c 3 python3 {remote}/host.py --role inviter --out {remoteout}']
commands={'inviter':cmd,'invitee':['python3',str(base/'host.py'),'--role','invitee','--out',str(out)]}
procs={}; q=queue.Queue(); keys={}
def reader(role,proc):
    with open(out/('controller-'+role+'.log'),'w') as log:
        for line in proc.stdout:
            log.write(line); log.flush(); q.put((role,line))
    q.put((role,None))
try:
    for role,command in commands.items():
        proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        procs[role]=proc; threading.Thread(target=reader,args=(role,proc),daemon=True).start()
    end=time.monotonic()+420; started=False; ended=set()
    while len(ended)<2:
        if time.monotonic()>end: raise RuntimeError('two-host run timeout')
        try: role,line=q.get(timeout=1)
        except queue.Empty: continue
        if line is None: ended.add(role); continue
        try: event=json.loads(line)
        except ValueError: print(role,line.strip(),flush=True); continue
        if event.get('phase')=='host-public-key':
            keys[role]=event['publicKey']
            if len(keys)==2:
                procs['invitee'].stdin.write(json.dumps({'peer':keys['inviter']})+'\n'); procs['invitee'].stdin.flush()
        if event.get('phase')=='waiting-for-invite' and role=='invitee' and not started:
            procs['inviter'].stdin.write(json.dumps({'peer':keys['invitee']})+'\n'); procs['inviter'].stdin.flush(); started=True
        if event.get('phase') not in ['catch-up-req','wire-publish']: print(json.dumps(event),flush=True)
    codes={role:proc.wait(timeout=20) for role,proc in procs.items()}
    subprocess.run(['scp','-q',f'ai395:{remoteout}/inviter.log',f'ai395:{remoteout}/inviter-result.json',f'ai395:{remoteout}/host-inviter.json',f'ai395:{remoteout}/net-inviter.jsonl',str(out)+'/'],check=True)
    results=[json.loads((out/(r+'-result.json')).read_text()) for r in ['inviter','invitee']]
    summary={'processExit':codes,'ok':all(r.get('ok') for r in results) and all(c==0 for c in codes.values()),'equalMlsFingerprint':results[0].get('groupFingerprint')==results[1].get('groupFingerprint'),**networks}
    summary['ok']=summary['ok'] and summary['equalMlsFingerprint']
    (out/'summary.json').write_text(json.dumps(summary,indent=2)); print(json.dumps(summary),flush=True)
    if not summary['ok']: sys.exit(1)
finally:
    for proc in procs.values():
        if proc.poll() is None: proc.terminate()
