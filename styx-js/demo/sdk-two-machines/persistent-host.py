#!/usr/bin/env python3
"""Prototype host supervisor. Secret key stays in this host's memory only."""
import argparse, fcntl, json, os, pathlib, secrets, shutil, signal, socket, subprocess, sys, tempfile, threading, time
p=argparse.ArgumentParser(); p.add_argument('--role',required=True); p.add_argument('--out',required=True); p.add_argument('--lock',action='store_true'); a=p.parse_args()
base=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(a.out).resolve(); out.mkdir(parents=True,exist_ok=True)
lock=None
if a.lock:
    lock=open('/home/mverde/reviews/styx-kanban/.ai395-test.lock','a'); fcntl.flock(lock,fcntl.LOCK_EX)
node=os.environ.get('DEMO_NODE','node')
scratch=pathlib.Path(os.environ.get('TMPDIR',str(pathlib.Path.home()/'.hermes/cache/scratch'))); scratch.mkdir(parents=True,exist_ok=True)
state=pathlib.Path(tempfile.mkdtemp(prefix='sdk-persistence-',dir=scratch)); state.chmod(0o700)
env={**os.environ,'DEMO_STATE_KEY':secrets.token_hex(32),'STATE_DIR':str(state),'ROLE':a.role}
child=None; generation=0; threads=[]; minimum=[2**64]; stopped=threading.Event(); errors=[]
logfile=open(out/(a.role+'-events.jsonl'),'a')
write_lock=threading.Lock()
def emit(e):
    e={'role':a.role,**e}
    with write_lock:
        line=json.dumps(e); logfile.write(line+'\n'); logfile.flush(); print(line,flush=True)
def available():
    return int(next(l for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:')).split()[1])*1024
def service():
    return subprocess.run(['systemctl','show','llama-swap','--property=MainPID','--value'],capture_output=True,text=True).stdout.strip()
before=service()
def guard():
    while not stopped.wait(1):
        minimum[0]=min(minimum[0],available())
        if socket.gethostname()=='AI395' and minimum[0]<15_000_000_000:
            errors.append('RAM floor'); emit({'phase':'guard-failure','error':'RAM floor'})
            if child and child.poll() is None: child.kill()
            return
threading.Thread(target=guard,daemon=True).start()
def reader(proc,g):
    for line in proc.stdout:
        try: e=json.loads(line)
        except ValueError: emit({'phase':'stderr','generation':g,'message':line.strip()}); continue
        emit({**e,'generation':g})
        if e.get('phase')=='crash-ready':
            proc.kill(); code=proc.wait(timeout=10)
            emit({'phase':'host-killed','generation':g,'signal':'SIGKILL','exit':code})
    code=proc.wait(); emit({'phase':'host-exit','generation':g,'exit':code})
try:
    minimum[0]=available()
    if socket.gethostname()=='AI395' and minimum[0]<15_000_000_000: raise RuntimeError('RAM floor')
    result=subprocess.check_output([node,str(base/'persistent-member.mjs')],env={**env,'PUBLIC_KEY_ONLY':'1'},text=True)
    emit({**json.loads(result),'hostname':socket.gethostname()})
    for line in sys.stdin:
        cmd=json.loads(line)
        if cmd['op']=='launch':
            if child and child.poll() is None: raise RuntimeError('previous generation running')
            for t in threads: t.join(timeout=10)
            generation+=1
            child=subprocess.Popen([node,str(base/'persistent-member.mjs')],env={**env,'PEER':cmd['peer'],'RELAYS':cmd['relays']},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
            t=threading.Thread(target=reader,args=(child,generation),daemon=True); threads.append(t); t.start()
        elif cmd['op']=='finish': break
        else:
            if not child or child.poll() is not None: raise RuntimeError('member not running')
            child.stdin.write(json.dumps(cmd)+'\n'); child.stdin.flush()
except Exception as e:
    errors.append(str(e)); emit({'phase':'host-failure','error':str(e)})
finally:
    if child and child.poll() is None:
        child.kill(); child.wait(timeout=10)
    for t in threads: t.join(timeout=10)
    modes={f.name:oct(f.stat().st_mode & 0o777) for f in state.iterdir()}
    directory_mode=oct(state.stat().st_mode & 0o777)
    # Only this supervisor's synthetic encrypted state, explicitly disposable.
    shutil.rmtree(state)
    stopped.set()
    result={'phase':'host-cleanup','stateRemoved':not state.exists(),'stateDirectoryMode':directory_mode,'fileModes':modes,'availableMinimum':minimum[0],'llamaSwapPidBefore':before,'llamaSwapPidAfter':service(),'errors':errors,'hostname':socket.gethostname()}
    (out/(a.role+'-host.json')).write_text(json.dumps(result,indent=2)); emit(result)
    logfile.close()
    if lock: lock.close()
if errors: sys.exit(1)
