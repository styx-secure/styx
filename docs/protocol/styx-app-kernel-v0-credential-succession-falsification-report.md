# C0.2j credential-succession falsification report

- **Status:** bounded executable evidence for the selected C0.2j candidate;
  independent exact-final review and human ratification remain mandatory.
- **Issue:** [#233](https://github.com/styx-secure/styx/issues/233)
- **Exact base:** `8f30f1940e4417fcb47b156b08c2242f405dc09b`
- **Model:** `tools/causal-flow-simulator/v3/`
- **Model identifier:** `styx.credential-succession-falsification/v3`

## 1. Verdict

The independently authored v3 symbolic model found **no counterexample within
the declared common envelope** for the selected grant-rooted, two-sided,
provenance-aware construction. All **24/24 required semantic mutants** were
killed. This is bounded negative evidence, not a mathematical proof, production
implementation, conformance corpus, audit or security certification.

The canonical outputs at this source state are:

| Artifact | SHA-256 |
| --- | --- |
| required witness report | `29cfda5ec83e4502be94c7635be1e592f98d083cf57b1489bf78b2b150b429ed` |
| mutation report | `4a3cf5e084ca05569a9979bd3536ecb2292fafe86e164eff123238bdfff5bb8a` |

The suite emits 31 directed assertions across 35 recorded projection runs and
22 closed witness families. Repeating either command produces byte-identical
JSON:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/causal-flow-simulator/v3/causal_flow_simulator_v3.py \
  --suite required --output /tmp/styx-c02j-v3.json
PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/causal-flow-simulator/v3/mutation_harness_v3.py \
  --suite required --output /tmp/styx-c02j-v3-mutants.json
sha256sum /tmp/styx-c02j-v3.json /tmp/styx-c02j-v3-mutants.json
```

## 2. Independence and retained evidence

V3 imports no v1/v2 module and copies no historical model file. Module-isolation
tests enforce that boundary. The new model retains and re-tests these C0.2i
properties without modifying historical evidence:

- an unavailable `REQUIRED` opening makes that event and its causal descendants
  pending without altering K admission;
- content or an opening never substitutes across events;
- checkpoint-only replay evidence remains stale and never substitutes for live
  authenticated history; and
- every K-admitted credential-control event remains in the authority evidence
  set regardless of AP pending, applicability, post-revocation or current fold
  outcome.

V3 deliberately supersedes these v2 assumptions:

- whole-context fork quarantine becomes credential-lineage quarantine;
- prefix-local grant-before-revoke authority becomes `MustAuth` expansion over
  all admissible interpretations;
- non-transitive revocation becomes bounded provenance termination;
- `ROTATE`/`RECOVER` placeholders become fresh-GRANT succession controls; and
- v2 incremental prefix reuse is not inherited. V3 claims fresh full replay
  only.

## 3. Common search envelope and work

| Dimension | Enforced bound | Maximum observed |
| --- | ---: | ---: |
| events | 12 | 5 |
| credential-control events | 6 | 4 |
| parents per event | 4 | 2 |
| credential lineage depth | 4 | 2 |
| topological orders | 720 | 3 |
| exhaustive delivery-permutation width | 6 | 3 |
| credentials | 10 | 5 |
| verification-key octets | 64 | 32 |

The model rejects bound overflow before computing any positive authority result.
`replayed_event_work` is reported as admitted events multiplied by explored
authority orders; no incremental cache or hidden checkpoint handoff is used.
These values are experiment bounds and do not select O-08 production limits.

## 4. Closed witness coverage

| Witness family | Directed evidence |
| --- | --- |
| identifier binding and cross-context | grant reference binds context, issuer, suite and key; cross-context/key/suite mutation rejects |
| duplicate grant and deliberate collision | byte-identical evidence is idempotent; declared subject and distinct-preimage collision fail closed |
| genesis domain separation | genesis credential IDs cannot equal grant event references |
| non-grant binding spoof | lookup-only use cannot create binding; AP bytes cannot supply K key material |
| unresolved dangling and forward author | both reject rather than defer or create pending state |
| grant/revoke grinding and delivery | attacker-selected grant references on both sides of revoke and all bounded delivery orders cannot bypass `MustAuth` |
| may-only reduction | possible authority can reduce; an actor revoked in every acting-prefix interpretation cannot |
| mutual concurrent revocation | both reductions apply; no canonical-order survivor is selected |
| multi-hop provenance containment | revoking each ancestor terminates descendants; independent fresh provenance can restore continuity |
| single compromised authority takeover | one uncontested authority can remove peers and remain sole producer; limitation recorded |
| re-grant and recovery non-resurrection | old ID cannot be rebound; legitimate recovery uses a fresh independent grant |
| alias evidence | independent same-key aliases are visible and independently revoked |
| rotation/recovery and old-key continuation | fresh grant plus retirement; concurrent revoke cannot resurrect the old credential |
| fork scope and privilege neutrality | one rule before/after grant, revoke, rotate and recovery; role/status cannot expand authority |
| independent authority continuation | unrelated definitely authorized lineage continues around a fork |
| pending required content with authority | pending/AP outcome never filters K authority evidence |
| checkpoint stale/no substitution | missing live dependency stays stale |
| logical removal against credential control | structurally inapplicable; binding and authority unchanged |
| control tail and content structure | malformed tails and content-bearing controls reject before AP |
| transport and case-ephemeral neutrality | account, session, Nostr, storage and UI facts are absent from authority |
| full-replay delivery convergence | equal authenticated sets produce one semantic view |
| bounded hostile flood | event/control/parent/order/lineage excess fails closed |

The canonical JSON contains the bidirectional machine-readable mapping from
each witness family to its assertions/mutants and from every mutant to its
killing witnesses.

## 5. Mutation result

All required mutants are killed:

```text
M01 identifier omits context
M02 identifier omits algorithm
M03 identifier omits issuer
M04 possession implies authority
M05 expansion uses MayAuth
M06 reduction requires MustAuth
M07 MayAuth reduction ignored
M08 one linearization decides authority
M09 provenance is non-transitive
M10 recovery resurrects a revoked identifier
M11 canonical order resolves mutual revocation
M12 non-GRANT creates a binding
M13 malformed credential-control tail accepted
M14 fork expands authority
M15 checkpoint substitutes for retained history
M16 same-key alias changes K/AP result
M17 incremental result diverges from fresh replay
M18 AP bytes supply K binding evidence
M19 revoked identifier is re-granted
M20 AP state filters the authority evidence set
M21 genesis credential uses event-reference domain
M22 content-bearing credential control accepted
M23 unresolved credential deferred
M24 terminally revoked actor reduces authority
```

The mutation harness requires both an observed failing assertion and a declared
witness-to-mutant edge. A mutant is not reported killed merely because some
unrelated check failed.

## 6. Frozen-interface verification

Before amendment, the exact O-06b-1 section-4 seven-role domain registry hashes
to:

```text
5b6bc4041b028ead4821cd7d33bb102255d7df728309e2e8bef232f16c9e3fb3
```

The amended document must retain that exact section hash. The byte-frozen
O-06b-2 section-6 commitment context hashes to:

```text
14bcde53d5534584e3cd1ba2503a3bb755df112ed0d42485cf9f1bef61b1f7f8
```

It remains unmodified. C0.2j adds role class `0x02` and its K-owned tail only;
it does not allocate an eighth hash domain, change the reference suite, alter
the logical-removal tail or modify the 44-octet commitment context.

## 7. Residual risks and non-claims

- A bounded search can miss behavior outside its envelope or a defect in the
  model itself.
- The symbolic reference calculation is not an independent exact-byte encoder
  and does not prove SHA-256 collision/second-preimage security.
- One uncontested compromised authority can still remove all peers and remain
  sole producer; no quorum or separation-of-duty rule is invented here.
- Mutual reductions or lineage quarantine can leave no operational authority.
- Revoking one credential does not revoke an independently granted same-key
  alias.
- Grant-rooted identifiers expose their binding grant to authorized observers
  and do not prove unlinkability.
- No checkpoint freshness, rollback, finality, irreversible effect, anonymity,
  implementation security, runtime capacity or sensitive-use claim follows.
- O-07, O-08, O-10 and O-14 remain open. C0.2k, O-06c and C0.3 remain blocked.

## 8. Acceptance interpretation

The result supports ratifying the selected C0.2j semantic contract only if the
normative documents, exact role tail and derived review model agree with this
report and exact-final independent review finds no blocking discrepancy. It
does not authorize a production implementation or relax any existing gate.
