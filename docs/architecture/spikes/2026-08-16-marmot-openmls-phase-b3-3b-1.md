# Phase B3.3b-1: sequential epoch evolution and recovery

Date: 2026-08-16

Issue: #188

Pull request: #189

Disposition: **bounded GO at the exact pinned revisions; merged as
`e2d63536fca756cecaed5f3862cc03ea41348e65`**

## Question and scope

B3.3b-1 asks whether the isolated Styx OpenMLS boundary and the pinned MDK peer
can execute sequential, proposal-free self-updates from either member, recover
publication and merge work after fresh-process restart, converge on the same
authenticated GroupContext, and still exchange application messages from the
immediately preceding epoch.

This is synthetic protocol evidence. It does not activate product code, PWA
behaviour, Nostr transport or a production retention policy.

## Frozen inputs

| Boundary | Exact value |
| --- | --- |
| Styx base commit | `83fb7b9255412e5e2f1ae96c1b5557e3a016939b` |
| OpenMLS commit / tree | `09e92777dba0528d3d29e2e5e681b7e91637c7be` / `fde242458abe5594fbebf2556dca0a135367a817` |
| Marmot commit / tree | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` / `10d941f358de5d9fe4ee1db75581f3e5363f5e92` |
| MDK commit / tree | `9396adb6aa6b95b521a7979facd5ea7040c07288` / `a1145de604e616634dae9a1ef6bf5033c9c9e879` |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) |
| Past-epoch retention | exactly five epochs in both engines |

The installed five-file tuple is:

| Artifact | SHA-256 | Bytes |
| --- | --- | ---: |
| `openmls_wasm.js` | `3de8fd46e4897aae117ee7b10ac41dffd02b507952c4024b0fe69d89fbb0c973` | 220234 |
| `openmls_wasm.d.ts` | `057974ec53e3588da3dbf159f183b3e3ddb4a3b0a57d5391194f124a483ede86` | 78278 |
| `openmls_wasm_bg.wasm` | `fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e` | 2358165 |
| `openmls_wasm_bg.wasm.d.ts` | `c21ace2360b264437541025e4703bcb38b53010793829d1904cb85b3d2aa238a` | 45291 |
| `package.json` | `88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85` | 449 |

Two clean locked builds produced the byte-identical tuple. The verifier binds
the installed files, the approved Rust patch and provenance record by SHA-256,
while remaining valid after the repository's mandatory squash merge.

## Result

The proof established all of the following at the frozen tuple:

- a local Commit is prepared once, persisted before publication and recovered
  byte-identically after restart;
- an inbound Commit is staged and validated before merge, then applied from
  durable state by a fresh process;
- MDK publication recovery and convergence use the pinned peer's public APIs;
- epoch, roster, GroupContext and accepted Commit identity agree after each
  transition;
- application traffic from the parent epoch is accepted in both directions and
  exact replay creates no second application output;
- malformed input, wrong group or epoch, replay, own echo, public proposals,
  invalid Commit forms, identity/profile drift, a third member, persistence
  failures and operation-sequence drift fail closed.

The exact reviewed candidate was
`fd270a0151baea90dfa95bf9f5f4b59fc42460af`, tree
`027c5d8ff5c9c4d1be457347e0452901b78cf6a7`. Its focused result was 37
OpenMLS tests, 8 locked MDK tests and 5 JavaScript suites / 31 tests. The full
JavaScript run passed 108 suites / 1538 tests, reproducible WASM verification
passed, and the PWA build and applicable CI gates were green.

DeepSeek V4 Pro reported no blocking finding on the exact candidate. The
independent human reviewer approved the exact final HEAD before the owner
performed the squash merge.

## Error and recovery semantics

The durable journal is authoritative. A prepared local transition cannot become
canonical until peer acceptance evidence is persisted; an inbound transition
cannot merge before staging and validation. Recovery selects only a contractually
valid action and never guesses past a malformed or ambiguous head. MDK and Styx
may expose different error labels, but neither difference is converted into a
successful transition.

## Non-claims and remaining work

- No concurrent same-parent fork or deterministic branch-selection result.
- No proof of the exact inclusive five-past-epoch boundary; that belongs to
  B3.3b-2a.
- No membership evolution, relay, anonymity, metadata-privacy, browser-vault,
  product-readiness, certification or general Marmot-conformance claim.
- The Styx-authored Rust/JavaScript boundary remains unaudited and
  `extensions-draft` remains an experimental pinned dependency.
- Five retained past epochs are an explicit security tradeoff for this isolated
  experiment, not a chosen shipping policy.

Rollback is the atomic revert of PR #189. All generated groups, identities and
private evidence state are synthetic and disposable.
