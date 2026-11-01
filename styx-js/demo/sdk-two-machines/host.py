#!/usr/bin/env python3
"""One host: ephemeral identity, own relay TLS capture, sanitized evidence.
Controller sends only the peer public key on stdin. No protocol-state transfer.
"""
import argparse, json, os, pathlib, secrets, socket, subprocess, sys, threading, time, tempfile, signal, hashlib, fcntl
p=argparse.ArgumentParser(); p.add_argument('--role', choices=['inviter','invitee'],required=True); p.add_argument('--out',required=True); a=p.parse_args()
base=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(a.out).resolve(); out.mkdir(parents=True,exist_ok=True)
node=os.environ.get('DEMO_NODE','node')
relays=['relay.nostr.net','relay.primal.net','offchain.pub']
seed=secrets.token_hex(32); env={**os.environ,'DEMO_SEED':seed}
key=subprocess.check_output([node,str(base/'member.mjs')],env={**env,'PUBLIC_KEY_ONLY':'1'},text=True).strip()
lock=None
if a.role=='inviter':
    lock=open('/home/mverde/reviews/styx-kanban/.ai395-test.lock','a'); fcntl.flock(lock,fcntl.LOCK_EX)
def available():
    values=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    return int(values['MemAvailable'].split()[0])*1024
baseline={'hostname':socket.gethostname(),'availableBefore':available(),'role':a.role}
if a.role=='inviter' and baseline['availableBefore'] < 15_000_000_000: raise RuntimeError('RAM floor')
baseline['llamaSwapPid']=subprocess.run(['systemctl','show','llama-swap','--property=MainPID','--value'],capture_output=True,text=True).stdout.strip()
addresses=set()
for h in relays:
    for info in socket.getaddrinfo(h,443,type=socket.SOCK_STREAM): addresses.add(info[4][0])
bpf='tcp port 443 and ('+' or '.join('host '+ip for ip in sorted(addresses))+')'
scratch=os.environ.get('TMPDIR',str(pathlib.Path.home()/'.hermes/cache/scratch'))
pathlib.Path(scratch).mkdir(parents=True,exist_ok=True)
capdir=pathlib.Path(tempfile.mkdtemp(prefix='sdk-nov-',dir=scratch)); os.chmod(capdir,0o700)
pcap=capdir/'relay.pcapng'; keys=capdir/'tls.keys'
capturelog=open(capdir/'capture.log','w')
cap=subprocess.Popen(['dumpcap','-q','-i','any','-f',bpf,'-a','duration:360','-w',str(pcap)],stdout=capturelog,stderr=capturelog)
member=None
def interrupted(signum, frame):
    raise SystemExit(128 + signum)
for signum in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]:
    signal.signal(signum, interrupted)
stop=threading.Event(); minimum=[baseline['availableBefore']]
def guard():
    while not stop.wait(2):
        minimum[0]=min(minimum[0],available())
        if a.role=='inviter' and minimum[0]<15_000_000_000:
            if member: member.terminate()
            return
threading.Thread(target=guard,daemon=True).start()
try:
    time.sleep(1)
    if cap.poll() is not None: raise RuntimeError('capture failed: '+(capdir/'capture.log').read_text())
    print(json.dumps({'phase':'host-public-key','publicKey':key,'role':a.role}),flush=True)
    peer=json.loads(sys.stdin.readline())['peer']
    if len(peer)!=64 or any(c not in '0123456789abcdef' for c in peer): raise RuntimeError('bad peer')
    env.update(ROLE=a.role, PEER=peer,OUT=str(out/(a.role+'-result.json')))
    member=subprocess.Popen([node,'--no-warnings','--tls-keylog='+str(keys),str(base/'member.mjs')],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    with open(out/(a.role+'.log'),'w') as log:
        for line in member.stdout:
            log.write(line); log.flush(); print(line,end='',flush=True)
    rc=member.wait(timeout=330)
    cap.send_signal(signal.SIGINT); cap.wait(timeout=15); capturelog.close()
    baseline.update(memberExit=rc,availableMinimum=minimum[0],availableAfter=available(),captureBytes=pcap.stat().st_size,pcapSha256=hashlib.sha256(pcap.read_bytes()).hexdigest())
    baseline['llamaSwapPidAfter']=subprocess.run(['systemctl','show','llama-swap','--property=MainPID','--value'],capture_output=True,text=True).stdout.strip()
    subprocess.run(['python3',str(base/'netview.py'),str(pcap),str(keys),a.role,','.join(relays),str(out/('net-'+a.role+'.jsonl'))],check=True)
    print(json.dumps({'phase':'host-result',**baseline}),flush=True)
finally:
    stop.set()
    if member and member.poll() is None: member.terminate(); member.wait(timeout=10)
    if cap.poll() is None: cap.send_signal(signal.SIGINT); cap.wait(timeout=10)
    capturelog.close()
    # Explicit demo-only permission: remove only this run's own keys and capture.
    for f in [keys,pcap]:
        if f.exists(): subprocess.run(['shred','-u',str(f)],check=True)
    (capdir/'capture.log').unlink(missing_ok=True); capdir.rmdir()
    baseline['transientCaptureAndKeysRemoved']=not capdir.exists()
    (out/('host-'+a.role+'.json')).write_text(json.dumps(baseline,indent=2))
    if lock: lock.close()
