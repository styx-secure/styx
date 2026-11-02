#!/usr/bin/env python3
"""Read-only HTTPS source capture. NEVER opens a public websocket or publishes."""
import concurrent.futures,datetime,json,pathlib,sys,urllib.request
out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
urls={
 'strfry-config':'https://raw.githubusercontent.com/hoytech/strfry/master/strfry.conf',
 'strfry-filter':'https://raw.githubusercontent.com/hoytech/strfry/master/src/filters.h',
 'nostr-rs-config':'https://raw.githubusercontent.com/scsibug/nostr-rs-relay/master/config.toml',
 'nostr-rs-sqlite':'https://raw.githubusercontent.com/scsibug/nostr-rs-relay/master/src/repo/sqlite.rs',
 'nostr-rs-postgres':'https://raw.githubusercontent.com/scsibug/nostr-rs-relay/master/src/repo/postgres.rs',
 'nip11-spec':'https://raw.githubusercontent.com/nostr-protocol/nips/master/11.md',
}
for host in ['relay.nostr.net','relay.primal.net','offchain.pub']:
 urls[host+'-nip11']='https://'+host+'/'
 urls[host+'-html']='https://'+host+'/'
def fetch(item):
 name,url=item;req=urllib.request.Request(url,headers={'Accept':'application/nostr+json' if name.endswith('-nip11') else 'text/html, text/plain;q=0.9','User-Agent':'Styx-read-only-research/1.0'})
 result={'name':name,'url':url,'fetchedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 try:
  with urllib.request.urlopen(req,timeout=30) as r:
   body=r.read();result.update(status=r.status,headers=dict(r.headers));(out/(name+'.txt')).write_bytes(body)
   if name.endswith('-nip11'):
    doc=json.loads(body);result['document']=doc;result['limitations']=doc.get('limitation');result['retention']=doc.get('retention');result['policyLinks']={k:v for k,v in doc.items() if any(s in k for s in ['terms','privacy','policy'])}
 except Exception as e:result['error']=str(e)
 return result
results=list(concurrent.futures.ThreadPoolExecutor(max_workers=6).map(fetch,urls.items()))
(out/'sources.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
