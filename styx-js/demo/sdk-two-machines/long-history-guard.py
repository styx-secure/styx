#!/usr/bin/env python3
"""AI395-only lock and memory/service guard for unchanged-SDK history runs."""
import fcntl,json,os,pathlib,socket,subprocess,time,sys
assert socket.gethostname()=='AI395'
out=pathlib.Path(os.environ['EVIDENCE_DIR']);out.mkdir(parents=True,exist_ok=True)
def memory():
    return int(next(l.split()[1] for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:')))*1024
def services():
    return subprocess.check_output(['systemctl','show','llama-swap','ds4-glm-full','ComfyUI','-p','Id','-p','ActiveState','-p','MainPID'],text=True)
with open('/home/mverde/reviews/styx-kanban/.ai395-test.lock','a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    before=services();minimum=memory();assert minimum>=15_000_000_000
    log=open(out/'run.log','w')
    proc=subprocess.Popen([os.environ['DEMO_NODE'],str(pathlib.Path(__file__).with_name('long-history-run.mjs'))],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    samples=[];violation=None
    try:
        while proc.poll() is None:
            free=memory();minimum=min(minimum,free);samples.append({'time':time.time(),'available':free})
            if free<15_000_000_000:violation='memory floor';break
            if services()!=before:violation='service state changed';break
            time.sleep(2)
    finally:
        if violation:
            import signal
            os.killpg(proc.pid,signal.SIGTERM)
        code=proc.wait();after=services()
        (out/'guard.json').write_text(json.dumps({'exit':code,'violation':violation,'minimumAvailable':minimum,'servicesBefore':before,'servicesAfter':after,'servicesUnchanged':before==after,'samples':samples},indent=2))
    sys.exit(1 if violation else code)
