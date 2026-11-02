#!/usr/bin/env python3
"""Recompute offline-recipient measurements from untouched raw JSON frames."""
import argparse, collections, hashlib, json, pathlib
p=argparse.ArgumentParser();p.add_argument('--root',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--runs',nargs='+');a=p.parse_args()
root=a.root.resolve()
names=a.runs or ['offline-public-before-'+n for n in ['04','05','06']]+['offline-public-after-'+n for n in ['02','03','04']]+['offline-local-before-01']
results=[]
for name in names:
    directory=root/name
    summary=json.loads((directory/'summary.json').read_text());assert summary['ok'],summary
    es=[json.loads(l) for l in (directory/'controller.jsonl').read_text().splitlines()]
    stop=next(e for e in es if e['phase']=='offline-start')
    restart=next(e for e in es if e['phase']=='restart-request')
    seconds=(restart['observedNs']-stop['observedNs'])/1e9
    assert seconds>=60
    exits=[e for e in es if e['phase']=='host-exit']
    assert collections.Counter(e['role'] for e in exits)=={'inviter':1,'invitee':2}
    assert all(e['exit']==0 for e in exits)
    assert next(e for e in exits if e['role']=='invitee' and e['generation']==1)['observedNs']<stop['observedNs']
    assert not any(e['role']=='invitee' and e['phase'] in ['wire','message'] and stop['observedNs']<e['observedNs']<restart['observedNs'] for e in es)
    assert len([e for e in es if e['phase']=='paired'])==2
    assert len([e for e in es if e['phase']=='started' and e['role']=='inviter'])==1
    restored=[e for e in es if e['phase']=='started' and e['role']=='invitee' and e['generation']==2];assert len(restored)==1
    initial=next(e for e in es if e['phase']=='public-key' and e['role']=='invitee')
    assert restored[0]['self']==initial['publicKey']
    assert restored[0]['fingerprint']==next(e['fingerprint'] for e in es if e['phase']=='paired')
    snapshots=[e for e in es if e['phase']=='snapshot' and e['role']=='inviter'];assert len(snapshots)==2
    before,final=snapshots
    assert before['deliveries']==summary['beforeRestartDeliveries']
    assert final['deliveries']==summary['finalDeliveries']
    assert set(final['deliveries'])=={'m1','m2','m3','m4'}
    wires=[e for e in es if e['phase']=='wire']
    assert not any(e['phase']=='failure' for e in es)
    assert not any(e['role']=='invitee' and e['generation']==2 and e['direction']=='out' and e['frame'][0]=='EVENT' and e['frame'][1]['kind'] in [4743,1059] for e in wires)
    records={}
    for id,status in final['deliveries'].items():
        eventid=status['eventId'];assert eventid
        outgoing=[e for e in wires if e['role']=='inviter' and e['direction']=='out' and e['frame'][0]=='EVENT' and e['frame'][1]['id']==eventid]
        assert outgoing and all(e['frame'][1]['kind']==4741 for e in outgoing)
        if id in ['m3','m4']:assert all(stop['observedNs']<e['observedNs']<restart['observedNs'] for e in outgoing)
        accepted=[e for e in wires if e['role']=='inviter' and e['direction']=='in' and e['frame'][0]=='OK' and e['frame'][1]==eventid and e['frame'][2] is True and e['observedNs']<restart['observedNs']]
        returns=[e for e in wires if e['role']=='invitee' and e['generation']==2 and e['direction']=='in' and e['frame'][0]=='EVENT' and e['frame'][2]['id']==eventid]
        callbacks=[e for e in es if e['phase']=='message' and e['role']=='invitee' and e['id']==id]
        assert len(callbacks)==1 and not callbacks[0]['duplicate']
        assert callbacks[0]['generation']==(1 if id in ['m1','m2'] else 2)
        receipts=[e for e in wires if e['role']=='inviter' and e['direction']=='in' and e['frame'][0]=='EVENT' and e['frame'][2]['kind']==4742 and ['e',eventid] in e['frame'][2]['tags']]
        assert all(e['frame'][2]['pubkey']==initial['publicKey'] for e in receipts)
        receiptids={e['frame'][2]['id'] for e in receipts}
        terminal=[e for e in es if e['phase']=='terminal' and e['role']=='inviter' and e['id']==id];assert len(terminal)==1 and terminal[0]['terminal']
        assert status['state']==terminal[0]['state']
        if id in ['m1','m2']:assert terminal[0]['state']=='RECIPIENT_RECEIPT_RECEIVED'
        else:
            assert callbacks[0]['observedNs']>restart['observedNs']
            assert len({e['relay'] for e in accepted})==3
            if summary['variant']=='before-deadline':
                assert before['deliveries'][id]['state']=='RELAY_ACCEPTED_AWAITING_RECEIPT'
                assert status['state']=='RECIPIENT_RECEIPT_RECEIVED'
                assert terminal[0]['at']<status['deadlineAt']
                assert any(e['at']<status['deadlineAt'] for e in receipts)
            else:
                assert before['deliveries'][id]['state']=='FAILED_NO_RECEIPT'
                assert status['state']=='FAILED_NO_RECEIPT'
                assert terminal[0]['observedNs']<restart['observedNs']
                assert receipts and all(e['at']>status['deadlineAt'] for e in receipts)
        records[id]={'eventId':eventid,'acceptedBeforeRestart':sorted({e['relay'] for e in accepted}),'returnedFrames':len(returns),'returnedUniqueIds':len({e['frame'][2]['id'] for e in returns}),'returnedByRelay':dict(collections.Counter(e['relay'] for e in returns)),'callbacksTotal':len(callbacks),'callbacksAfterRestart':sum(e['generation']==2 for e in callbacks),'receiptFrames':len(receipts),'receiptUniqueIds':len(receiptids),'firstReceiptAt':min((e['at'] for e in receipts),default=None),'firstReceiptAfterDeadline':bool(receipts) and min(e['at'] for e in receipts)>status['deadlineAt'],'receiptAfterDeadlineFrames':sum(e['at']>status['deadlineAt'] for e in receipts),'terminal':status['state'],'lastCode':status['lastCode'],'deadlineAt':status['deadlineAt'],'terminalAt':terminal[0]['at']}
    discards=collections.Counter(e['code'] for e in es if e['role']=='invitee' and e.get('generation')==2 and e['phase']=='discard')
    reqs=[{'relay':e['relay'],'filter':e['frame'][2]} for e in wires if e['role']=='invitee' and e['generation']==2 and e['direction']=='out' and e['frame'][0]=='REQ']
    assert reqs and all('since' not in e['filter'] for e in reqs[:3])
    cleanups=[e for e in es if e['phase']=='host-cleanup'];assert len(cleanups)==2
    for c in cleanups:
        assert c['stateRemoved'] and not c['errors'] and c['stateDirectoryMode']=='0o700' and set(c['fileModes'].values())=={'0o600'}
        host=json.loads((directory/(c['role']+'-host.json')).read_text())
        for k in ['stateRemoved','availableMinimum','llamaSwapPidBefore','llamaSwapPidAfter']:assert c[k]==host[k]
        if c['hostname']=='AI395':assert c['availableMinimum']>=15_000_000_000 and c['llamaSwapPidBefore']==c['llamaSwapPidAfter']=='7744'
    if summary['relayMode']=='public':assert summary['distinctPublicEgress']
    results.append({'run':name,'variant':summary['variant'],'relayMode':summary['relayMode'],'offlineSeconds':seconds,'messages':records,'discardCodesOnRestart':dict(discards),'aliceDiscardCodes':dict(collections.Counter(e['code'] for e in es if e['role']=='inviter' and e['phase']=='discard')),'restoredReqs':reqs,'minimumAvailableAi395':next(c['availableMinimum'] for c in cleanups if c['hostname']=='AI395'),'cleanup':True})
if not a.runs:
    assert len(results)==7
    assert collections.Counter((r['relayMode'],r['variant']) for r in results)=={('public','before-deadline'):3,('public','after-deadline'):3,('local','before-deadline'):1}
failures=[]
for directory in sorted(root.glob('offline-*/summary.json')):
    s=json.loads(directory.read_text())
    if not s['ok']:failures.append({'directory':directory.parent.name,'error':s.get('error')})
pilots=['offline-public-before-02','offline-public-before-03','offline-public-after-01']
for name in pilots:assert json.loads((root/name/'summary.json').read_text())['ok']
interrupted=json.loads((root/'offline-interrupted-hashes.json').read_text())
assert all(hashlib.sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in interrupted.items())
aggregate={'ok':True,'runs':results,'countFinalRuns':len(results),'pilotCompleted':len(pilots),'pilotDirectories':pilots,'failedAttempts':failures,'previousInterruptedUnchanged':True,'totalCallbacks':sum(m['callbacksTotal'] for r in results for m in r['messages'].values()),'offlineMessages':sum(m['callbacksAfterRestart'] for r in results for id,m in r['messages'].items() if id in ['m3','m4']),'lateReceiptMessages':sum(m['firstReceiptAfterDeadline'] for r in results for id,m in r['messages'].items() if id in ['m3','m4']),'minimumAvailableAi395':min(r['minimumAvailableAi395'] for r in results)}
a.output.write_text(json.dumps(aggregate,indent=2))
print(json.dumps({k:v for k,v in aggregate.items() if k!='runs'},indent=2))
for r in results:print(json.dumps({'run':r['run'],'offlineSeconds':r['offlineSeconds'],'replayedFrames':[m['returnedFrames'] for m in r['messages'].values()],'discardCodes':r['discardCodesOnRestart'],'states':[m['terminal'] for m in r['messages'].values()]}))
