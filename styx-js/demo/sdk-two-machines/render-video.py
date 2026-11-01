#!/usr/bin/env python3
"""Render a 100s evidence playback, not a live screen recording. Run on AI395."""
import argparse, json, pathlib, subprocess, textwrap
from PIL import Image, ImageDraw, ImageFont
p=argparse.ArgumentParser(); p.add_argument('--evidence',required=True); p.add_argument('--out',required=True); a=p.parse_args()
evidence=pathlib.Path(a.evidence).resolve(); out=pathlib.Path(a.out).resolve(); out.mkdir(parents=True,exist_ok=True)
ares=json.loads((evidence/'inviter-result.json').read_text()); bres=json.loads((evidence/'invitee-result.json').read_text())
assert ares['ok'] and bres['ok'] and ares['groupFingerprint']==bres['groupFingerprint']
net=[json.loads(l) for role in ['inviter','invitee'] for l in (evidence/('net-'+role+'.jsonl')).read_text().splitlines()]
def select(role,phases):
    return [s for s in (ares if role=='inviter' else bres)['steps'] if s['phase'] in phases]
def brief(s):
    if 'view' in s:
        if s['view'] == 'wire': return 'wire / ' + s['text']
        return 'ws / ' + s['text'] + ' / kind=' + str(s.get('kind')) + ' / contentPrefix=' + s.get('content', '')[:110] + '... / contentChars=' + str(len(s.get('content', '')))
    return s['at'][11:23]+' '+s['role']+' '+s['phase']+' '+json.dumps({k:v for k,v in s.items() if k not in ['at','ms','role','phase']},ensure_ascii=False)
scenes=[
 (8,'01 / TWO HOSTS, TWO NETWORKS',['SDK '+ares['interfaceVersion'],'MVLINNA: invitee | AI395: inviter','Three public relays: nostr.net / primal.net / offchain.pub','Synthetic data, pre-audit. PROTOTYPE - DO NOT MERGE.','Evidence playback from actual JSON logs and packet captures.'],[]),
 (16,'02 / INVITATION OVER NOSTR',['KeyPackage: kind 4743. Encrypted Welcome: NIP-59 kind 1059.','No KeyPackage, Welcome or MLS state is copied between hosts.','Expected inviter public key is pinned by the invitee.'],select('invitee',['keypackage-published','mls-ready'])+select('inviter',['invite-published','mls-ready'])),
 (14,'03 / MESSAGES AND RECIPIENT RECEIPTS',['Three synthetic messages and three replies.','Relay acceptance is not the same as a recipient receipt.'],[s for s in select('inviter',['send','delivery-terminal','message-received']) if s.get('text') in ['synthetic message 1','synthetic reply 1']]+[s for s in select('invitee',['send','delivery-terminal']) if s.get('text')=='synthetic reply 1']),
 (16,'04 / R1 EXCLUDED, THEN A LOCAL STALL',['Only the inviter process excludes R1. The public relay stays up.','R2/R3 frames are blackholed both ways until attempt 1 times out.'],select('inviter',['fault'])[:3]+[s for s in select('inviter',['delivery-state']) if s['deliveryId']=='d3'][:3]),
 (16,'05 / RETRY AND CATCH-UP',['R2/R3 restored; the SDK retries message 3.','Reply 2 was sent during the stall and recovered once after return.'],select('inviter',['stall-cleared'])+[s for s in select('invitee',['send']) if s.get('text')=='synthetic reply 2']+[s for s in select('inviter',['catch-up-req']) if s['ms']>=next(x['ms'] for x in ares['steps'] if x['phase']=='stall-cleared')][:2]+[s for s in select('inviter',['message-received','delivery-terminal']) if s.get('text') in ['synthetic reply 2','synthetic message 3']]),
 (20,'06 / WIRE VIEW AND OWN TLS DECRYPTION',['On path: TLS records, sizes and timing (IPs masked).','After removing our own TLS: message events still carry MLS ciphertext.','KeyPackages and metadata are public; this is not anonymity.'],[s for s in net if s['view']=='wire' and 'TLS' in s['text']][:2]+[s for s in net if s.get('kind')==4741][:2]),
 (10,'07 / MEASURED RESULT AND LIMITS',['6 / 6 messages have RECIPIENT_RECEIPT_RECEIVED.','Equal hash of a shared MLS exporter on both members.','One local relay exclusion; one stall, retry and recovered reply.','No audit, anonymity, production-readiness or general outage guarantee.','Experimental kinds; volatile identity/session state; no attacker trial here.','No SDK, crypto or vendor changes. Nothing merged.'],select('inviter',['result'])+select('invitee',['result']))
]
assert sum(s[0] for s in scenes)==100
fonts='/usr/share/fonts/truetype/dejavu/'
title=ImageFont.truetype(fonts+'DejaVuSans-Bold.ttf',28); body=ImageFont.truetype(fonts+'DejaVuSans.ttf',21); mono=ImageFont.truetype(fonts+'DejaVuSansMono.ttf',16)
manifest=[]; playlist=[]
for index,(duration,name,notes,lines) in enumerate(scenes):
    img=Image.new('RGB',(1280,720),'#101820'); d=ImageDraw.Draw(img)
    d.text((35,25),'STYX / CLIENT SDK / PUBLIC RELAYS',font=body,fill='#63d4c3'); d.text((35,68),name,font=title,fill='white')
    y=120
    for note in notes:
        for line in textwrap.wrap(note,105): d.text((35,y),line,font=body,fill='#cfdae5'); y+=29
    y+=15; d.rectangle((25,y,1255,675),fill='#080e14'); y+=12
    rendered=[]
    for line in lines:
        # Keep exact source objects in the manifest; shortened text is display-only.
        parts=textwrap.wrap(brief(line),117)
        for part in parts[:4]:
            if y>647: break
            d.text((38,y),part,font=mono,fill='#8fe2ae'); y+=21
        if y>647: break
        y+=5; rendered.append(line)
    filename=out/f'scene-{index:02d}.png'; img.save(filename)
    d.text((35,690),'Evidence playback / synthetic data, pre-audit / not an unedited live recording',font=mono,fill='#9aabba'); img.save(filename)
    manifest.append({'scene':name,'durationSeconds':duration,'notes':notes,'sourceLines':rendered})
    playlist.extend(["file '"+str(filename)+"'",'duration '+str(duration)])
playlist.append("file '"+str(filename)+"'")
(out/'scenes.txt').write_text('\n'.join(playlist)+'\n'); (out/'video-source-lines.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False))
subprocess.run(['ffmpeg','-hide_banner','-loglevel','error','-y','-f','concat','-safe','0','-i',str(out/'scenes.txt'),'-t','100','-vf','fps=10,format=yuv420p','-c:v','libx264','-preset','fast','-crf','22','-threads','2','-movflags','+faststart',str(out/'sdk-two-machines-2026-11.mp4')],check=True)
print(subprocess.check_output(['ffprobe','-v','error','-show_entries','format=duration,size','-of','json',str(out/'sdk-two-machines-2026-11.mp4')],text=True))
