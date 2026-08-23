# C0.2j credential-succession falsification report

- **Status:** bounded executable evidence for the selected C0.2j candidate;
  independent exact-final review and human ratification remain mandatory.
- **Issue:** [#233](https://github.com/styx-secure/styx/issues/233)
- **Exact base:** `8f30f1940e4417fcb47b156b08c2242f405dc09b`
- **Model:** `tools/causal-flow-simulator/v3/`
- **Model identifier:** `styx.credential-succession-falsification/v3`

## 1. Verdict

The independently authored v3 symbolic model found **no counterexample within
the declared common envelope** for the selected grant-rooted, Pass0/first-slot,
provenance-aware construction. All **45/45 required semantic mutants** were
killed. This is bounded negative evidence, not a mathematical proof, production
implementation, conformance corpus, audit or security certification.

The canonical outputs at this source state are:

| Artifact | SHA-256 |
| --- | --- |
| required witness report | `c2328dc7c2fd7c93d52e93d2832395b1a88d9c9934c136158dbde973bf35f41a` |
| mutation report | `6d18a699ab3a974aaa60c68475d6e2c8b06551dd2d29fc57d6e24c62e1ee833b` |

The suite emits 69 directed assertions across 73 recorded projection runs and
36 closed witness families. Repeating either command produces byte-identical
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
- prefix-local grant-before-revoke authority becomes Pass0 `Must0` expansion
  over all admissible interpretations plus a bounded first eligible contested
  reduction slot per actor credential;
- non-transitive revocation becomes bounded provenance termination;
- `ROTATE`/`RECOVER` placeholders become fresh-GRANT succession controls; and
- v2 incremental prefix reuse is not inherited. V3 claims fresh full replay
  only, implemented by reachable-state dynamic programming with the factorial
  linearization engine retained solely as a bounded oracle.

## 3. Common search envelope and work

| Dimension | Enforced bound |
| --- | ---: |
| events | 18 |
| credential-control events | 6 |
| same-sequence fork slots | 6 |
| parents per event | 4 |
| credential lineage depth | 4 |
| factorial-oracle topological orders | 720 |
| reachable authority states | 65,536 |
| reachable authority transitions | 524,288 |
| exhaustive delivery-permutation width | 6 |
| credentials | 10 |
| verification-key octets | 64 |

Across the required suite the observed maxima were **4,033** authority states,
**14,556** main-fold authority transitions, **174,672** ordinary-probe authority
transitions, **189,246** units of total replay work, lineage depth **4** and
**7,484,400** represented complete topological paths. Total replay work includes
each admitted event, the main authority fold and every ordinary-event acting-
prefix probe; the probe cost is not hidden. The path count is evidence carried
by DP state aggregation, not a production acceptance gate.

The model rejects event, control, fork, parent, lineage, credential, key and
author-sequence overflow before computing any positive authority result. A
reachable-state or transition overflow instead returns one typed whole-projection
unavailable result and exposes no partial or empty-authority substitute. No
incremental cache or hidden checkpoint handoff is used. These values are the
C0.2j experiment envelope and do not select O-08 product limits.

## 4. Closed witness coverage

| Witness family | Directed evidence |
| --- | --- |
| identifier binding and cross-context | grant reference binds context, issuer, suite and key; cross-context/key/suite mutation rejects |
| duplicate grant and deliberate collision | byte-identical evidence is idempotent; declared subject and distinct-preimage collision fail closed |
| genesis domain separation | genesis credential IDs cannot equal grant event references |
| non-grant binding spoof | lookup-only use cannot create binding; AP bytes cannot supply K key material |
| unresolved dangling and forward author | both reject rather than defer or create pending state |
| author-chain and frontier canonicality | distinct sequences follow predecessor continuity while sibling forks share one author-sequence slot |
| grant/revoke grinding and delivery | attacker-selected references and bounded delivery orders cannot bypass Pass0 `Must0` expansion |
| bounded contested standing | each actor receives at most one first eligible contested slot; all eligible siblings in it are applied without a reference winner |
| may-only reduction | a Pass0 `May0`-only reduction can use the bounded slot; an actor unauthorized in every interpretation cannot |
| mutual concurrent revocation | both eligible reductions apply; no canonical-order survivor is selected |
| self- and cross-lineage standing | self-lineage attempts consume no slot while an eligible peer-directed sibling remains selectable |
| successor reduction standing | rejected expansion does not erase historical K evidence or create recursive standing |
| causal-target availability | unresolved and resolvable non-causal reduction targets reject before AP authority evaluation |
| omitted-history issuer veto | R-1 blocks a direct unseen-target veto but not a non-acknowledging reduction of the visible issuer and its later grant descendants |
| non-genesis causal-target cleanup | an authorized issuer that observed the binding grant can clean up the non-genesis target |
| multi-hop provenance containment | revoking each ancestor terminates descendants; independent fresh provenance can restore continuity |
| intermediate revocation recovery | revoking an honest intermediate blocks one measured descendant expansion while an independently authorized untainted issuer can re-grant |
| bounded subtree amplification | one accepted reduction may terminate a five-credential witness subtree but cannot create another contested slot |
| single compromised authority takeover | one uncontested authority can remove peers and remain sole producer; limitation recorded |
| re-grant and recovery non-resurrection | old ID cannot be rebound; legitimate recovery uses a fresh independent grant |
| compromised-provenance recovery | a replacement rooted in May0-only compromised provenance remains bound evidence but cannot expand operational authority |
| alias evidence | independent same-key aliases are visible, independently revoked and retain separate credential-local fork namespaces |
| rotation/recovery and old-key continuation | fresh grant plus retirement; concurrent revoke cannot resurrect the old credential, and a replacement authored by the retiring lineage remains non-operational |
| fork scope and privilege neutrality | one rule before/after grant, revoke, rotate and recovery; role/status cannot expand authority |
| already-revoked fork | later sibling evidence remains a fork and cannot restore the revoked lineage |
| fork acknowledgment boundary | a virtual fork join follows all siblings and precedes evidence that acknowledges their complete set |
| fork after reduction and fork twin | late fork evidence never resurrects a reduced credential or lets a sibling expand authority |
| forked-descendant containment | lineage quarantine follows bounded provenance descendants rather than the whole context |
| independent authority continuation | unrelated definitely authorized lineage continues around a fork |
| ordinary-event prefix authority | ordinary events query compatible Pass0 acting-prefix states without becoming control-order items |
| outcome precedence | structural, stale, resource-unavailable, fork, pending, removal, post-revocation, lineage and authority combinations produce exactly one primary outcome |
| pending required content with authority | pending/AP outcome never filters K authority evidence |
| checkpoint stale/no substitution | missing live dependency stays stale and exposes no authority result |
| logical removal against credential control | structurally inapplicable; binding and authority unchanged |
| control tail and content structure | malformed tails and content-bearing controls reject before AP |
| transport and case-ephemeral neutrality | account, session, Nostr, storage and UI facts are absent from authority |
| full-replay delivery convergence | equal authenticated sets produce one semantic view |
| bounded hostile flood | event/control/fork/parent/lineage/state/transition excess fails closed with typed results |
| independent budget accounting | five controls, one two-way ordinary fork and one ordinary authority probe coexist; the probe adds measured replay work but consumes neither control nor fork budget |
| transitive control causality | causal ancestry, not delivery or event-reference order, controls target availability and prefix authority |

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
M05 expansion uses Pass0 May0
M06 reduction requires Pass0 Must0
M07 May0-only reduction ignored
M08 one linearization decides authority
M09 provenance is non-transitive
M10 recovery resurrects a revoked identifier
M11 canonical order resolves mutual revocation
M12 non-GRANT creates a binding
M13 malformed credential-control tail accepted
M14 fork expands authority
M15 checkpoint substitutes for retained history
M16 same-key alias changes K/AP result
M17 terminal authority set is tampered
M18 AP bytes supply K binding evidence
M19 revoked identifier is re-granted
M20 AP state filters the authority evidence set
M21 genesis credential uses event-reference domain
M22 content-bearing credential control accepted
M23 unresolved credential deferred
M24 terminally revoked actor reduces authority
M25 distinct-preimage collision selects a winner
M26 provenance termination follows only direct dependencies
M27 a credential fork terminates every lineage globally
M28 author-chain continuity is not enforced
M32 a virtual fork join is evaluated before its sibling evidence
M33 ordinary events use terminal rather than acting-prefix authority
M34 contested reductions are unbounded
M35 a non-causal reduction target is accepted
M36 recovery incorrectly requires retired-target ancestry
M37 a filtered or rejected May0 reduction is incorrectly applied as a Pass-2 accepted termination
M38 contested standing is recursively seeded to a fixed point
M39 cross-lineage reductions select a canonical winner
M40 contested selection is grindable by event reference
M41 a terminated descendant receives fresh contested standing
M42 a May0-only self-lineage reduction is accepted
M43 self-rotation is accepted
M44 an ordinary authority probe becomes a control-order item
M45 factorial order count becomes the production gate
M46 authority-state overflow is encoded as empty authority
M47 the DP state key omits authority
M48 primary-outcome precedence drifts
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
  alias, and such aliases retain separate credential-local fork namespaces.
- The first-slot exception deliberately preserves one contested peer-reduction
  opportunity per actor credential. Independently granted credentials and
  same-key aliases therefore multiply standing within the common envelope.
- One selected reduction can terminate a bounded descendant subtree: at most
  nine credentials structurally under the ten-credential cap and five in the
  executable six-control witness.
- A rejected later-slot or excluded self-lineage reduction can permanently lower
  Pass0 `Must0` for its target subtree even though it cannot become an accepted
  reduction. The accepted first-slot bound is not an operational availability
  bound; the latter is bounded here only by the common evidence envelope.
- R-1 prevents direct omitted-history vetoes against unseen later grants, but an
  attacker can indirectly lower `Must0` for future grants by reducing their
  visible issuer. Mutual concurrent
  reductions of independent non-genesis credentials reject unless the actors
  causally observed one another's binding grant. Cleanup therefore depends on an
  authorized issuer path and is not guaranteed.
- Self-lineage reductions and self-rotation reject; this avoids self-budget
  laundering but provides no out-of-band recovery.
- An accepted `ROTATE` retirement does not make its referenced replacement
  operational. A replacement `GRANT` authored by the retiring lineage can be
  K-valid yet fail Pass0 `Must0`, so profiles need an independently authorized
  recovery path and must not claim atomic authority transfer.
- A valid evidence set beyond a DP state or transition limit makes the entire
  authority projection unavailable until a future profile migration or
  admissible reduction of the evidence set.
- A checkpoint-only replay dependency makes every authority result unavailable;
  an empty encoded authority set in that state is not evidence of no authority.
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
