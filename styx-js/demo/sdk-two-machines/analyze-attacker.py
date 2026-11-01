#!/usr/bin/env python3
"""Read-only attribution of synthetic public-relay trials; no SDK internals."""
import collections, datetime, json, pathlib
root = pathlib.Path(__file__).resolve().parent
output = []
def epoch(s):
    return datetime.datetime.fromisoformat(s['at'].replace('Z', '+00:00')).timestamp()
for p in sorted((root/'evidence-attacker').glob('run-*')):
    if not (p/'summary.json').exists():
        continue
    results = {r: json.loads((p/(r+'-result.json')).read_text()) for r in ['inviter','invitee']}
    mallory = json.loads((p/'mallory-log.json').read_text())
    release = next(s for s in results['invitee']['steps'] if s['phase']=='true-receipt-release')
    terminal = next(s for s in results['inviter']['steps'] if s['phase']=='delivery-terminal')
    attacks = []
    for attack in mallory['attacks']:
        ids = sorted(set(attack['ids']))
        hosts = {}
        for role, result in results.items():
            steps = result['steps']
            net = [json.loads(line) for line in (p/('net-'+role+'.jsonl')).read_text().splitlines()]
            per_id = {}
            for eid in ids:
                raw = [s for s in steps if s['phase']=='raw-observed' and s.get('eventId')==eid]
                wire = [s for s in steps if s['phase']=='sdk-wire-in' and s.get('eventId')==eid]
                # Public callbacks omit event id. Only record immediate adjacency,
                # not a stronger claim of SDK-provided id attribution.
                adjacent = [steps[i+1] for i,s in enumerate(steps[:-1]) if s['phase']=='sdk-wire-in' and s.get('eventId')==eid and steps[i+1]['phase']=='inbound-discarded']
                per_id[eid] = {'rawCount': len(raw), 'sdkSocketCount':len(wire), 'sanitizedCaptureInboundPrefixCount':sum(x.get('eid')==eid[:8] and not x.get('out') for x in net), 'firstSocketAt':wire[0]['at'] if wire else None, 'adjacentDiscards':adjacent}
            hosts[role] = per_id
        attacks.append({'name':attack['name'], 'ids':ids, 'relayAnswer':attack['relayAnswer'], 'hosts':hosts})
    false_ids = set(next(a for a in attacks if a['name']=='forged receipt')['ids'])
    false_wire = [s for s in results['inviter']['steps'] if s['phase']=='sdk-wire-in' and s.get('eventId') in false_ids]
    first_false = min(map(epoch,false_wire))
    snapshots = [s for s in results['inviter']['steps'] if s['phase']=='pending-snapshot' and first_false < epoch(s) < epoch(release)]
    assert snapshots and all(not s['terminal'] and s['state']=='RELAY_ACCEPTED_AWAITING_RECEIPT' for s in snapshots)
    assert epoch(terminal) >= epoch(release)
    for role,r in results.items():
        expected = 'synthetic honest reply' if role=='inviter' else 'synthetic attacker target'
        assert r['ok'] and len(r['received'])==1 and r['received'][0]['text']==expected and r['received'][0]['sender']==r['peer']
    for name in ['injection','tamper']:
        a = next(x for x in attacks if x['name']==name)
        assert any(v['sdkSocketCount'] for v in a['hosts']['invitee'].values())
    hosts = {r:json.loads((p/('host-'+r+'.json')).read_text()) for r in results}
    assert all(h['transientCaptureAndKeysRemoved'] for h in hosts.values())
    assert hosts['inviter']['availableMinimum'] >= 15_000_000_000
    assert hosts['inviter']['llamaSwapPid']==hosts['inviter']['llamaSwapPidAfter']!='0'
    assert json.loads((p/'networks.json').read_text())['distinctPublicEgress']
    assert not json.loads((p/'worker-health-final.json').read_text())['armed']
    record = {'run':p.name,'ok':True,'attacks':attacks,'receivedCounts':{r:len(x['received']) for r,x in results.items()}, 'discardCodes':{r:dict(collections.Counter(s['code'] for s in x['steps'] if s['phase']=='inbound-discarded')) for r,x in results.items()},'pendingSnapshotsAfterFalseReceipt':len(snapshots),'lastPendingAt':snapshots[-1]['at'],'trueReleaseAt':release['at'],'terminalAt':terminal['at'],'receiptDelaySeconds':epoch(terminal)-epoch(next(s for s in results['inviter']['steps'] if s['phase']=='send')),'hosts':hosts}
    (p/'attribution.json').write_text(json.dumps(record,indent=2))
    output.append(record)
(root/'evidence-attacker/aggregate.json').write_text(json.dumps({'completeRuns':len(output),'runs':output},indent=2))
print(json.dumps({'completeRuns':len(output),'results':[{'run':r['run'],'discardCodes':r['discardCodes'],'pendingSnapshots':r['pendingSnapshotsAfterFalseReceipt'],'receiptDelaySeconds':r['receiptDelaySeconds']} for r in output]},indent=2))
