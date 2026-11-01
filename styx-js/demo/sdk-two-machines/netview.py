#!/usr/bin/env python3
"""netview.py -- turn one host's capture of the relay connections into two masked, time-stamped text views.

usage: netview.py <pcap> <tls-keylog> <hostLabel> <relay1,relay2,relay3> <out.jsonl>

  view 'wire': one line per relevant packet exactly as any on-path observer can decode it WITHOUT keys
               (TCP SYN/FIN/RST, TLS record sizes, SNI hostname). No decryption.
  view 'ws'  : the WebSocket frames after removing TLS with this host's OWN TLS session keys (the NSS key log
               written by `node --tls-keylog`), i.e. what the relay operator receives / sends.

Masking: our own address (any side whose port is not 443) is replaced by <hostLabel>; every remote address
by the relay hostname taken from the TLS SNI of that TCP stream (R1/R2/R3 labels). No IP address is written
to the output. The tshark JSON (which does contain addresses) is only held in memory.
tshark receives pcapng on stdin; TLS secrets are injected only in the in-memory pipe.
No AppArmor rule is changed and no system /tmp path is used.
"""
import json, subprocess, sys, re, struct

PCAP, KEYS, HOST, RELAYS, OUT = sys.argv[1:6]
RELAYS = RELAYS.split(',')
F = ['frame.number', 'frame.time_epoch', 'tcp.stream', 'tcp.srcport', 'tcp.dstport', 'frame.len', 'tcp.len',
     'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.fin', 'tcp.flags.reset', 'tls.handshake.type',
     'tls.handshake.extensions_server_name', 'tls.record.content_type', 'tls.record.opaque_type', 'tls.record.length',
     'tls.handshake.random', 'websocket.opcode', 'websocket.payload.text', 'tls.app_data']


def tshark(extra, decrypt=False):
    # Stream the capture on stdin: no AppArmor changes and no /tmp exceptions.
    with open(PCAP, 'rb') as fh:
        data = fh.read()
    if decrypt:
        with open(KEYS, 'rb') as fh:
            secret = fh.read()
        # Standard pcapng Decryption Secrets Block, TLS Key Log type.
        # It exists only in RAM / the pipe, never in a retained capture.
        endian = '<' if data[8:12] == b'\x4d\x3c\x2b\x1a' else '>'
        headlen = struct.unpack_from(endian + 'I', data, 4)[0]
        padded = secret + b'\0' * ((-len(secret)) % 4)
        total = 20 + len(padded)
        dsb = struct.pack(endian + 'IIII', 10, total, 0x544c534b, len(secret)) + padded + struct.pack(endian + 'I', total)
        data = data[:headlen] + dsb + data[headlen:]
    cmd = ['tshark', '-r', '-', '-T', 'json'] + extra
    for f in F:
        cmd += ['-e', f]
    run = subprocess.run(cmd, input=data, capture_output=True)
    if run.returncode:
        raise RuntimeError('tshark failed: ' + run.stderr.decode(errors='replace'))
    return [p['_source']['layers'] for p in json.loads(run.stdout or b'[]')]


def g(p, k, i=0):
    v = p.get(k)
    return v[i] if v and len(v) > i else None


plain = tshark([])
# Retain only TCP streams whose ClientHello matches THIS node's key log.
# No unrelated process traffic is written to the sanitized evidence.
with open(KEYS) as fh:
    randoms = {line.split()[1].lower() for line in fh if line.strip() and not line.startswith('#')}
own_streams = {g(p, 'tcp.stream') for p in plain if (g(p, 'tls.handshake.random') or '').replace(':', '').lower() in randoms}
plain = [p for p in plain if g(p, 'tcp.stream') in own_streams]
if not own_streams:
    raise RuntimeError('No own TLS streams found; capture is not evidence')
sni = {}
for p in plain:
    s = g(p, 'tls.handshake.extensions_server_name')
    if s:
        sni[g(p, 'tcp.stream')] = s
label = {}
for st, s in sni.items():
    label[st] = f'R{RELAYS.index(s) + 1} {s}' if s in RELAYS else s
lines = []


def emit(t, view, text, **kw):
    lines.append(dict(t=float(t), view=view, text=text, **kw))


def ends(p):
    st = g(p, 'tcp.stream')
    out = g(p, 'tcp.dstport') == '443'
    rl = label.get(st, f'relay? (stream {st})')
    return (HOST, rl) if out else (rl, HOST), out


TYPES = {'20': 'ChangeCipherSpec', '21': 'Alert', '22': 'Handshake', '23': 'ApplicationData'}
HS = {'1': 'ClientHello', '2': 'ServerHello'}
for p in plain:
    (src, dst), out = ends(p)
    t = g(p, 'frame.time_epoch')
    ln = g(p, 'frame.len')
    if g(p, 'tcp.flags.syn') in ('1', 'True', 'true') and g(p, 'tcp.flags.ack') in ('0', 'False', 'false'):
        emit(t, 'wire', f'{src} -> {dst}  TCP SYN (new connection) {ln} B', out=out)
    elif g(p, 'tcp.flags.reset') in ('1', 'True', 'true'):
        emit(t, 'wire', f'{src} -> {dst}  TCP RST {ln} B', out=out)
    elif g(p, 'tcp.flags.fin') in ('1', 'True', 'true'):
        emit(t, 'wire', f'{src} -> {dst}  TCP FIN (connection closed) {ln} B', out=out)
    elif p.get('tls.record.content_type') or p.get('tls.record.opaque_type'):
        hs = [HS.get(x, None) for x in p.get('tls.handshake.type', [])]
        hs = [h for h in hs if h]
        # TLS 1.3: encrypted records carry only an outer (opaque) type, always ApplicationData
        recs = [TYPES.get(x, x) for x in (p.get('tls.record.content_type', []) + p.get('tls.record.opaque_type', []))]
        lens = p.get('tls.record.length', [])
        if hs:
            desc = ' + '.join(hs) + (f" SNI={g(p, 'tls.handshake.extensions_server_name')}" if 'ClientHello' in hs else '')
        else:
            desc = 'TLS ' + ', '.join(f'{r} {l} B' for r, l in zip(recs, lens))
            ad = (g(p, 'tls.app_data') or '').replace(':', '')
            if ad:
                desc += f' {ad[:16]}…'
        emit(t, 'wire', f'{src} -> {dst}  {desc}  [{ln} B on wire]', out=out)

HEX = re.compile(r'"([0-9a-f]{64,128})"')


def shorten(js):
    return HEX.sub(lambda m: '"' + m[1][:8] + '…"', js)


dec = tshark(['-Y', 'websocket'], decrypt=True)
for p in dec:
    if g(p, 'tcp.stream') not in own_streams:
        continue
    (src, dst), out = ends(p)
    t = g(p, 'frame.time_epoch')
    for txt in p.get('websocket.payload.text', []) or []:
        txt = txt.replace('\\\\', '\\')
        info = {}
        try:
            m = json.loads(txt)
            if m[0] == 'EVENT':
                ev = m[-1]
                info = dict(kind=ev.get('kind'), eid=ev.get('id', '')[:8], content=ev.get('content', ''))
        except Exception:
            pass
        emit(t, 'ws', f'{src} -> {dst}', frame=shorten(txt), **info, out=out)
    if not p.get('websocket.payload.text') and g(p, 'websocket.opcode') in ('8', '9', '10'):
        op = {'8': 'Close', '9': 'Ping', '10': 'Pong'}[g(p, 'websocket.opcode')]
        emit(t, 'ws', f'{src} -> {dst}', frame=f'<WebSocket {op}>', out=out)

if not any(x['view'] == 'ws' and x.get('kind') == 4741 for x in lines):
    raise RuntimeError('TLS extraction has no MLS message event; not valid evidence')
lines.sort(key=lambda x: x['t'])
with open(OUT, 'w') as fh:
    for x in lines:
        fh.write(json.dumps(x, ensure_ascii=False) + '\n')
streams = sorted(set(label.values()))
print(f'{HOST}: packets {len(plain)}, wire lines {sum(1 for x in lines if x["view"] == "wire")}, '
      f'ws frames {sum(1 for x in lines if x["view"] == "ws")}, relays seen: {streams}')
