#!/usr/bin/env python3
"""Verify counts and raw evidence before making demo claims."""
import argparse, json, pathlib, collections, datetime
p=argparse.ArgumentParser(); p.add_argument('runs',nargs='+'); p.add_argument('--out',required=True); a=p.parse_args()
reports=[]
for directory in a.runs:
    root=pathlib.Path(directory); summary=json.loads((root/'summary.json').read_text())
    assert summary['ok'] and summary['equalMlsFingerprint'] and summary['distinctPublicEgress']
    results={role:json.loads((root/(role+'-result.json')).read_text()) for role in ['inviter','invitee']}
    assert results['inviter']['groupFingerprint']==results['invitee']['groupFingerprint']
    for role,r in results.items():
        assert r['ok'] and len(r['deliveries'])==3 and len(r['received'])==3
        assert all(d['state']=='RECIPIENT_RECEIPT_RECEIVED' for d in r['deliveries'])
        expected=[('synthetic reply ' if role=='inviter' else 'synthetic message ')+str(n) for n in range(1,4)]
        assert collections.Counter(x['text'] for x in r['received'])==collections.Counter(expected)
        assert all(x['sender']==r['peer'] for x in r['received'])
    inv=results['inviter']; guest=results['invitee']
    assert inv['deliveries'][2]['attempts']>=2
    dropped=next(s for s in inv['steps'] if s['phase']=='fault' and s['mode']=='down')
    assert dropped['relay']=='wss://relay.nostr.net'
    begin=next(s for s in inv['steps'] if s['phase']=='fault' and s['mode']=='blackhole')
    end=next(s for s in inv['steps'] if s['phase']=='stall-cleared')
    sent=next(s for s in guest['steps'] if s['phase']=='send' and s['text']=='synthetic reply 2')
    recv=next(s for s in inv['steps'] if s['phase']=='message-received' and s['text']=='synthetic reply 2')
    assert begin['at']<sent['at']<end['at']<recv['at']
    netcounts={}
    for role in results:
        host=json.loads((root/('host-'+role+'.json')).read_text())
        assert host['transientCaptureAndKeysRemoved'] and host['memberExit']==0
        if role=='inviter':
            assert host['availableMinimum']>=15_000_000_000
            assert host['llamaSwapPid']==host['llamaSwapPidAfter']!='0'
        lines=[json.loads(l) for l in (root/('net-'+role+'.jsonl')).read_text().splitlines()]
        ws=[l for l in lines if l['view']=='ws']; wire=[l for l in lines if l['view']=='wire']
        kinds=collections.Counter(l.get('kind') for l in ws if l.get('kind'))
        assert all(kinds[k]>0 for k in [4743,1059,4741,4742]) and wire
        for line in lines:
            assert 'synthetic message' not in line.get('frame','') and 'synthetic reply' not in line.get('frame','')
        for host_name in ['relay.nostr.net','relay.primal.net','offchain.pub']:
            assert any(host_name in l['text'] for l in lines)
        netcounts[role]={'wireLines':len(wire),'websocketFrames':len(ws),'kinds':dict(kinds)}
    recovery=(datetime.datetime.fromisoformat(recv['at'])-datetime.datetime.fromisoformat(end['at'])).total_seconds()
    reports.append({'run':root.name,'ok':True,'messages':6,'recipientReceipts':6,'attemptsMessage3':inv['deliveries'][2]['attempts'],'recoveredReply2SecondsAfterReturn':recovery,'capture':netcounts})
output={'ok':True,'completeRuns':len(reports),'totalMessages':sum(r['messages'] for r in reports),'totalRecipientReceipts':sum(r['recipientReceipts'] for r in reports),'runs':reports}
pathlib.Path(a.out).write_text(json.dumps(output,indent=2)); print(json.dumps(output,indent=2))
