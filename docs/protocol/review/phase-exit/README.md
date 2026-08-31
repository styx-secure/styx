# Protocol-hardening phase exit evidence

This directory contains the deterministic mechanical report for Issue #287.
It evaluates the eleven exit conditions in
`docs/protocol/protocol-hardening-plan.md` without deciding the two external
human gates.

Canonical mechanical record:

- mechanical eligibility: `ELIGIBLE_FOR_BOUNDED_GO`;
- `EXIT-08` and `EXIT-09`: `HUMAN_GATE_PENDING` in the canonical report by
  design, because the verifier cannot satisfy either human gate;
- operational phase status: declared exclusively by the versioned status block
  at the end of this document after live provider validation;
- capability authorization: never follows from the mechanical report or from
  Issue #287 alone.

Regenerate the report from a clean checkout at the exact candidate with:

```bash
python3 tools/protocol-phase-exit/verify.py \
  --repo-root . \
  --base fd6f652af1666c6c9dca8356c2aed615773f5208 \
  --output docs/protocol/review/phase-exit/phase-exit-report.json \
  --refresh-canonical-report
```

The committed report must be byte-identical in two clean worktrees. A passing
mechanical report is evidence for a later human verdict; it is not itself a
phase verdict and does not end the freeze.

During Phase A, the executor refreshes the canonical report only by targeting
that exact path with `--refresh-canonical-report`; the resulting bytes are then
committed. Every ordinary verification omits that flag, regenerates to an
external path, refuses to overwrite existing evidence and fails closed unless
the committed report is byte-identical.

Provider-bound Phase-B verification uses isolated Python with site loading
disabled. The exact IDs and digests come from the ratified live objects. The
provider path uses the absolute system interpreter, safe-path mode, and stores
both each unmodified REST response and its validated projection outside the
repository:

```bash
/usr/bin/python3 -I -S -B tools/protocol-phase-exit/verify.py \
  --repo-root . \
  --base fd6f652af1666c6c9dca8356c2aed615773f5208 \
  --output "$TMPDIR/phase-exit-report.json" \
  --verdict-comment-id "$VERDICT_COMMENT_ID" \
  --phase-a-head "$PHASE_A_HEAD" \
  --phase-a-report-sha256 "$PHASE_A_REPORT_SHA256" \
  --issue-provider-raw-output "$TMPDIR/issue-provider.raw.json" \
  --provider-raw-output "$TMPDIR/verdict-provider.raw.json" \
  --provider-output "$TMPDIR/verdict-provider.json" \
  --approval-review-id "$APPROVAL_REVIEW_ID" \
  --final-head "$FINAL_HEAD" \
  --approval-provider-raw-output "$TMPDIR/approval-provider.raw.json" \
  --approval-provider-output "$TMPDIR/approval-provider.json"
```

The verifier resolves every supplied commit through Git, proves
`Base -> Phase-A HEAD -> final HEAD`, requires the final HEAD to be checked out,
hashes the canonical report directly from the Phase-A commit, and permits only
the closed Phase-B status transformation defined by the contract. It also
fetches the live Issue and verifies the exact ratified body digest. Caller
proxy, CA, OpenSSL and Python import-path overrides are removed before TLS is
imported, and provider verification accepts only `/usr/bin/python3`.

<!-- styx-protocol-phase-exit-status:v1:start -->
Protocol-hardening phase-exit status: `BOUNDED_GO`. The broad protocol freeze has ended
only for work separately authorized under Section 9 of the hardening plan. Issue #287
itself authorizes no adapter, authenticated persistence, SDK, transport/delivery, product,
demo, deployment or sensitive-use work; US-001 through US-008 remain paused.
<!-- styx-protocol-phase-exit-status:v1:end -->
