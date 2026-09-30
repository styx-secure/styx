# M2-TRIG witness — the scope-evidence control on a `m2/integration` base

Stacked on `task/m2-trig` (`cabc1ddf3eb09bed858a8bff93a86092514e61c3`), base `m2/integration`
(`827702227814bd909e7fbce0cff1a6aa9eb13e23`). Contract Issue #352. This file is the witness pull
request's only added path; it is documentation and changes no behaviour.

What this pull request demonstrates:

- the `Agent scope evidence` workflow now starts for a pull request whose base is `m2/integration`
  (it produced no run at all before this card, e.g. on witness PR #349);
- the control decides this pull request with the **base** commit's adapter, scope guard and contract
  parser — the report's `execution_id` names `tool-827702227814bd909e7fbce0cff1a6aa9eb13e23`, not
  the head;
- the verdict is PASS because every changed path (`task/m2-trig`'s two allowlisted files plus this
  one) matches the contract's allowlist.

The sibling negative-probe pull request adds a path that is not in the allowlist and is reported
FAIL by the same base-side tooling.
