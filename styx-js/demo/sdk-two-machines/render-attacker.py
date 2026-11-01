#!/usr/bin/env python3
"""Evidence montage (not screen recording). Run encoding only on AI395."""
import argparse,json,pathlib,subprocess,textwrap
from PIL import Image,ImageDraw,ImageFont
p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);p.add_argument('--out',required=True);a=p.parse_args()
e=pathlib.Path(a.evidence);out=pathlib.Path(a.out);out.mkdir(parents=True,exist_ok=True)
agg=json.loads((e/'aggregate.json').read_text());assert agg['completeRuns']>=3
r=agg['runs'][0];b=e/r['run'];inv=json.loads((b/'inviter-result.json').read_text());rec=json.loads((b/'invitee-result.json').read_text())
def steps(result,phase):return [s for s in result['steps'] if s['phase']==phase]
def attack(name):return next(a for a in r['attacks'] if a['name']==name)
def excerpt(obj):return json.dumps(obj,ensure_ascii=False)
scenes=[
(10,'01 / PROTOTIPO: DUE NODI, TERZO ESECUTORE',['MONTAGGIO DELLE EVIDENZE REALI - non ripresa dal vivo','Invitante AI395; invitato MVLINNA; attaccante Cloudflare Worker.','Solo dati sintetici; nessuna chiave del gruppo al Worker.','Tre relay pubblici; API pubblica SDK; nessuna modifica SDK.'],[{'run':r['run'],'host':h['hostname'],'captureBytes':h['captureBytes']} for h in r['hosts'].values()]),
(12,'02 / INVITO E SESSIONE MLS',['KeyPackage 4743; Welcome incapsulato in gift wrap 1059.','Le chiavi del gruppo non passano dal coordinatore.','Identita effimere; hash esportatore MLS uguale sui due nodi.'],steps(inv,'mls-ready')+steps(rec,'mls-ready')),
(14,'03 / REPLAY E MANOMISSIONE',['Replay: stesso id; i relay segnalano duplicato.','Copia alterata senza nuova firma: due relay la respingono.','Copia rifirmata: arriva al socket, ma non all’applicazione.','Non confondere deduplicazione relay con prova isolata anti-replay SDK.'],[{'name':attack('replay')['name'],'relayAnswer':attack('replay')['relayAnswer']},{'name':'tamper','relayAnswer':attack('tamper')['relayAnswer']},steps(rec,'inbound-discarded')[0]]),
(14,'04 / INIEZIONE DA NON MEMBRO',['Evento 4741 firmato con chiave propria dell’attaccante.','Relay lo accetta; osservatore grezzo e socket SDK lo vedono.','E_SDK_SESSION_FAILED; nessun messaggio applicativo aggiuntivo.','Il callback non espone id: correlazione per adiacenza, non causale forte.'],[{'ids':attack('injection')['ids'],'relayAnswer':attack('injection')['relayAnswer']},steps(rec,'inbound-discarded')[-1]]),
(20,'05 / RICEVUTA FALSA, VERA TRATTENUTA',['Ricevute 4742 false effettivamente arrivate al socket del mittente.','La ricevuta vera resta trattenuta per 110 secondi.','Nessuna conferma anticipata; attesa fino alla ricevuta vera.','Nessun codice di scarto per queste ricevute: limite di osservabilita.'],[{'falseReceiptIds':attack('forged receipt')['ids']},{'pendingSnapshotsAfterFalseReceipt':r['pendingSnapshotsAfterFalseReceipt'],'lastPendingAt':r['lastPendingAt']},{'trueReleaseAt':r['trueReleaseAt'],'terminalAt':r['terminalAt']}]),
(16,'06 / RISULTATI RIPETUTI E IGIENE',['Tre esecuzioni complete; un messaggio e una risposta per esecuzione.','Nessun messaggio estraneo; consegne concluse con ricevuta vera.','Catture e key log eliminati su entrambi gli host dopo estrazione.','Indirizzi IP mascherati; llama-swap invariato; RAM oltre 15 GB.'],[{'run':x['run'],'received':x['receivedCounts'],'delaySeconds':round(x['receiptDelaySeconds'],3),'discardCodes':x['discardCodes']} for x in agg['runs']]),
(14,'07 / LIMITI E CONCLUSIONE',['Nessun attacco osservato ha prodotto payload o ricevute applicative false.','Non e un audit, una prova di anonimato o una garanzia universale.','Replay invariato filtrato dai relay; callback senza id di scarto.','Worker pilotato da tick esterni; metadati pubblici, stato volatile.','Ramo prototipo separato; nulla unito.'],[{'completeRuns':agg['completeRuns'],'sdkChanged':False,'merged':False}])]
assert sum(x[0] for x in scenes)==100
f='/usr/share/fonts/truetype/dejavu/';title=ImageFont.truetype(f+'DejaVuSans-Bold.ttf',27);body=ImageFont.truetype(f+'DejaVuSans.ttf',21);mono=ImageFont.truetype(f+'DejaVuSansMono.ttf',16)
manifest=[];playlist=[]
for i,(duration,name,notes,objects) in enumerate(scenes):
 image=Image.new('RGB',(1280,720),'#101820');d=ImageDraw.Draw(image);d.text((30,24),'STYX / CLIENT SDK / PROVA DIFENSIVA AUTORIZZATA',font=body,fill='#63d4c3');d.text((30,67),name,font=title,fill='white');y=120
 for note in notes:
  for line in textwrap.wrap(note,100):d.text((30,y),line,font=body,fill='#d5e0e9');y+=29
 y+=12;d.rectangle((24,y,1256,675),fill='#080e14');y+=10
 shown=[]
 for obj in objects:
  if y>630:break
  shown.append(obj)
  for line in textwrap.wrap(excerpt(obj),116)[:5]:
   if y>650:break
   d.text((34,y),line,font=mono,fill='#8fe2ae');y+=21
  y+=7
 d.text((30,690),'Montaggio delle evidenze / dati sintetici / prototipo non sottoposto ad audit',font=mono,fill='#9aabba');path=out/f'scene-{i:02d}.png';image.save(path)
 manifest.append({'scene':name,'durationSeconds':duration,'notes':notes,'sourceObjects':shown});playlist.extend(["file '"+str(path.resolve())+"'",'duration '+str(duration)])
playlist.append("file '"+str(path.resolve())+"'");(out/'scenes.txt').write_text('\n'.join(playlist)+'\n');(out/'video-source-lines.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False))
subprocess.run(['ffmpeg','-hide_banner','-loglevel','error','-y','-f','concat','-safe','0','-i',str(out/'scenes.txt'),'-t','100','-vf','fps=10,format=yuv420p','-c:v','libx264','-preset','fast','-crf','22','-threads','2','-movflags','+faststart',str(out/'sdk-attaccante-2026-11.mp4')],check=True)
print(subprocess.check_output(['ffprobe','-v','error','-show_entries','format=duration,size','-of','json',str(out/'sdk-attaccante-2026-11.mp4')],text=True))
