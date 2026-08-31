# Protocol-hardening phase exit evidence

This directory contains the deterministic Phase-A report for Issue #287.
It evaluates the eleven exit conditions in
`docs/protocol/protocol-hardening-plan.md` without deciding the two external
human gates.

Current state:

- mechanical eligibility: `ELIGIBLE_FOR_BOUNDED_GO`;
- `EXIT-08`: `HUMAN_GATE_PENDING`;
- `EXIT-09`: `HUMAN_GATE_PENDING`;
- protocol-hardening freeze: **still active**;
- adapter, persistence, SDK, transport/delivery, product, demo, deployment and
  sensitive use: **not authorized**.

Regenerate the report from a clean checkout at the exact candidate with:

```bash
python3 tools/protocol-phase-exit/verify.py \
  --repo-root . \
  --base 636c12c7da68fde309767732c42284f92b83ade3 \
  --output docs/protocol/review/phase-exit/phase-exit-report.json
```

The committed report must be byte-identical in two clean worktrees. A passing
mechanical report is evidence for a later human verdict; it is not itself a
phase verdict and does not end the freeze.
