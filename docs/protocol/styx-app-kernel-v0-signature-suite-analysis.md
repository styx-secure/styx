# Styx O-14 signature-suite analysis

- **Status:** selected bounded candidate; executable falsification and exact-final
  review remain authoritative gates.
- **Issue:** [#246](https://github.com/styx-secure/styx/issues/246).
- **Exact base:** `94f0a9b2781d45324199e6588629d23babedf746`.
- **Scope:** application-credential signature semantics only. This document does
  not modify or certify product cryptography.

## 1. Decision summary

The selected v0 baseline candidate is the internal Styx suite `0x0001`, named
`STYX-ED25519-PRIMEORDER-RFC8032-V1`. It is pure Ed25519 with:

- one exactly 32-octet RFC 8032 canonical compressed Edwards public key;
- one exactly 64-octet signature `R || S`, where `R` is a canonical 32-octet
  compressed Edwards point and `0 <= S < L` is little-endian;
- rejection of small-order points and of every decoded `A` or `R` outside the
  prime-order subgroup;
- the complete regenerated O-06b-1 application-event transcript as the message;
- a guard followed by exactly one pinned RFC 8032 verifier invocation; and
- terminal failure, with no alternate suite, library default, transport/session
  substitution, retry or fallback.

After the prime-order guards, the RFC 8032 cofactored equation
`[8][S]B = [8]R + [8][k]A` and the cofactorless equation
`[S]B = R + [k]A` admit the same guarded inputs: every term is in the
prime-order subgroup and multiplication by eight is invertible modulo `L`.
The selected profile therefore permits a pinned cofactored verifier only behind
both prime-order guards. A raw cofactored verifier is not this suite.

The namespace is an internal Styx `u16` registry. `0x0000`, `0xffff`, every
unassigned value and every future value are invalid. The identical number in a
digest-suite or third-party registry has no semantic relationship. A future
suite needs a separately ratified profile transition and cross-version
evidence; adding a dependency or accepting another algorithm cannot change the
meaning of `0x0001`.

## 2. Primary-source inventory

| Subject | Exact identity | Use and limitation |
| --- | --- | --- |
| RFC Ed25519 | [RFC 8032 §5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7) | Defines decoding, `S < L` and permits either the cofactored equation or the sufficient cofactorless alternative; the citation alone therefore does not select one accepted language. |
| WebCrypto Ed25519 | [Web Cryptography Level 2, 22 April 2025 FPWD, §25.3.2](https://www.w3.org/TR/2025/WD-webcrypto-2-20250422/#ed25519-operations-verify) | Requires canonical decoding, `S < L`, invalid/small-order `A` and `R` rejection and the cofactorless equation; also warns that implementations may omit checks. The exact versioned URI is normative for this analysis. |
| ZIP-215 | [ZIP 215](https://zips.z.cash/zip-0215) | Defines consensus-oriented permissive point decoding and the cofactored equation. It is compared, not selected. The published page exposes no immutable source revision in its protocol identifier, so none is fabricated here. |
| JavaScript Ed25519 | `@noble/ed25519@2.3.0`; registry URL `https://registry.npmjs.org/@noble/ed25519/-/ed25519-2.3.0.tgz`; npm integrity `sha512-M7dvXL2B92/M7dw9+gzuydL8qn/jiqNHaoR3Q+cb1q1GHV7uwE17WCyFMG+Y+TZb5izcaXk5TdJRrDUxHXL78A==` | Exact artifact pinned by `styx-js/package-lock.json`. The artifact carries a package version and upstream repository URL, but no source-commit revision; no commit is invented. |
| Dart Ed25519 | `cryptography@2.9.0`; archive URL `https://pub.dev/api/archives/cryptography-2.9.0.tar.gz`; SHA-256 `3eda3029d34ec9095a27a198ac9785630fe525c0eb6a49f3d575272f8e792ef0` | Exact pub.dev artifact used by the Dart probe. Its published metadata carries the version and repository URL, but no source-commit revision. |
| ECDSA comparison | [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final), [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) and the exact WebCrypto draft above | Establishes that a P-256 profile must additionally settle deterministic/randomized signing, low-`S`, public-key encoding and raw-versus-DER signature encoding. It is not selected. |

External official vectors may supplement the independently generated harness
only from a caller-selected temporary directory with exact revision, digest and
license recorded. No third-party vector byte is tracked by this task.

## 3. Candidate comparison

| Candidate | Accepted language and runtime surface | Decision |
| --- | --- | --- |
| RFC 8032 cofactored | Canonical `A`/`R`, `S < L`, cofactored equation; admits mixed-order and small-order-component constructions that the authorization profile need not accept. | Rejected as too permissive without prime-order guards. |
| WebCrypto Level 2 | Canonical points, `S < L`, rejects invalid/small-order `A`/`R`, cofactorless equation. Mixed-order points are not categorically excluded. | Useful comparison, but raw provider behavior is not a portable protocol definition. |
| Prime-order-constrained Ed25519 | Canonical points, `S < L`, both `A` and `R` non-small and torsion-free before one verifier. Cofactored/cofactorless equations then agree. | **Selected as `0x0001`**, subject to the bounded adapter and residual-risk conditions below. |
| ZIP-215 | Permissive decoding plus cofactored equation, intended for consensus compatibility. The harness exhibits non-canonical and mixed-order acceptances. | Rejected for an application authorization boundary. |
| Noble default | `verifyAsync(signature,message,key)` defaults to ZIP-215 in 2.3.0. | Unsafe as implicit protocol semantics; rejected. |
| Noble `{zip215:false}` | Canonical decoding and small-order `A` rejection, but still cofactored and without a separate small-order `R` or prime-subgroup requirement. | Raw call rejected; usable only after the exact selected guards. |
| Dart `DartEd25519.verify` | Canonical decompression, `S < L`, cofactorless equation in 2.9.0; no public API establishes the selected prime-order guards. | Raw call is not a conforming adapter. |
| Native WebCrypto | Provider-dependent implementation of the Level 2 operation. Node/OpenSSL is measured here, never generalized to browsers. | Raw call is not a conforming adapter; Node evidence becomes conforming only with the exact Noble guards. Browser matrix remains future evidence. |
| Fixed P-256 | Broad hardware/runtime availability, but requires new choices for point and signature encoding, low-`S`, nonce generation and downgrade migration. | Not needed for the v0 property; rejected for baseline selection. |
| Multi-suite/per-event negotiation | Expands downgrade, dispatch and migration state without a property unavailable to one-suite v0. | Rejected. |
| Nostr, MLS, transport or session signature | Authenticates a different layer and transcript. | Rejected as layer substitution. |
| No selection | Correct outcome if guarded runtime equality, source identity or evidence fails. | Retained as fail-closed `NO-GO`. |

## 4. Exact verification boundary

K processes an application credential signature in this order:

1. Regenerate the complete O-06b-1 application-event transcript.
2. Resolve `credential_identifier` through the monotone O-02 map to exactly one
   `(context, issuer, suite_id, verification_key_octets, grant_reference)`.
3. Reject missing, context-inconsistent, inactive, stale-sequence or otherwise
   state-invalid credentials independently of signature mathematics.
4. Read suite and verification key only from that authenticated binding. Ignore
   event, `GRANT` tail, transport, Nostr, MLS and session algorithm/key hints for
   verification of the carrying event.
5. Reject every suite except `0x0001`, then reject key/signature lengths other
   than 32/64 before proportional allocation or backend invocation.
6. Canonically decode `A` and `R`, require `S < L`, reject small-order points and
   require `A.isTorsionFree()` and `R.isTorsionFree()`.
7. Invoke exactly one pinned verifier over the full regenerated transcript.
   Failure is terminal. Batch, aggregate, fallback and retry verification are
   prohibited unless a future ratified transition proves exact accepted-language
   equality for every admitted input.
8. Expose a K-valid event to AP only after verification succeeds. AP authority,
   replay status and effect permission remain separate checks.

A true result proves only that the bound signing key produced a valid signature
over those bytes. It does not prove human identity, truth, originality,
uniqueness, authority, priority, finality or permission for an irreversible
effect. O-10 still owns public outcome codes; O-14 uses internal test labels.

## 5. Guarded adapters and measured raw disagreement

The required run used Node `v24.18.0` with OpenSSL `3.5.7`, Dart SDK `3.10.8`
and the exact artifacts above. Twenty-six runtime vectors included ordinary,
malformed, non-canonical, small-order and both directions of mixed-order
equation separation.

Two non-oracle adapters matched the selected language for every vector:

1. **Noble guarded:** `Point.fromBytes(bytes, false)`, `isSmallOrder()` and
   `isTorsionFree()` for `A` and `R`, scalar comparison against `CURVE.n`, then
   exactly one `verifyAsync(signature,message,key,{zip215:false})` call.
2. **Node WebCrypto guarded:** the same Noble guards, then exactly one
   `webcrypto.subtle.verify({name:'Ed25519'},key,signature,message)` call.

Raw backends diverged as follows:

- Noble default accepted the non-canonical-key, both cofactored-only mixed-order,
  cofactorless-valid mixed-order and small-order-`R` hostile witnesses.
- Noble `{zip215:false}` accepted both cofactored-only mixed-order,
  cofactorless-valid mixed-order and small-order-`R` hostile witnesses.
- Node/OpenSSL WebCrypto accepted the non-canonical-key and
  cofactorless-valid mixed-order hostile witnesses.
- Dart `cryptography` accepted the cofactorless-valid mixed-order hostile
  witness.

The Dart dependency exposes no public exact prime-order point-validation API.
Within this task's no-product-change and no-new-dependency boundary there is no
bounded conforming Dart adapter. This is residual risk
`O14-DART-PROFILE-NONCONFORMANCE`: before any Dart product claims suite `0x0001`
support, a separately ratified gate must select and audit an exact subgroup
guard or a conforming pinned verifier and replay the complete O-14 evidence.

Node WebCrypto is evidence only for the named Node/OpenSSL provider. A browser
matrix is residual obligation `O14-BROWSER-PROVIDER-MATRIX`; each supported
browser/provider must run the same raw and guarded vectors before a support
claim. A runtime/dependency upgrade reopens adapter evidence even when the suite
identifier does not change.

## 6. Reopen-predicate disposition

O-06b-1 section 8 is not reopened by the selected candidate:

1. the signed transcript and prehash semantics are unchanged;
2. Ed25519 authenticates the bounded arbitrary transcript octet string;
3. suite selection remains derived from authenticated credential state;
4. SHA-256 remains the independently selected event-reference digest and is not
   replaced by the signature's internal SHA-512 use;
5. no different event-reference digest or material additional production
   primitive is required for the demonstrated Noble adapter; and
6. every admitted `0x0001` key has one canonical 32-octet encoding and bound.

The C0.2j exact tail/key bound is satisfied by `u16 suite_id` plus a framed
32-octet verification key, so its signature-suite predicate is not met. The
suite introduces no clock, expiry, certificate or other time-bearing validity,
so O-12 is not reopened.

The O-06 record's own predicate is not met: the selected suite authenticates the
unchanged bytes without per-event selection, fallback or a materially different
digest/runtime basis. However, O-06c's existing placeholder-substitution duty is
**not discharged here**. Its six modules rerun the unchanged O-14 placeholder.
Before any C0.3 corpus can be authorized, a separate human-ratified task must
insert the selected suite/key/signature semantics into the combined O-06c
construction and rerun the complete evidence.

## 7. Decision limits

Selection is bounded negative evidence, not proof. It does not authorize product
code, a wire field, storage, C0.3, a corpus, an audit claim, interoperability,
anonymity, availability, erasure, finality, compliance or sensitive use. The
current CI does not execute the O-14 evidence; exact report digests and two clean
worktree reproductions are the task gate.

O-14 can become condition-bearing `DECIDED` only while the executable evidence,
adapter non-vacuity, independent reviews and human gates remain green. O-07,
O-08, O-10 and corpus-path approval stay open; C0.3 stays `NO_GO`.
