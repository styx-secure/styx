# Evidence status observation

`tools/evidence-status/evidence_status.py` is an offline diagnostic observer for
existing Styx v1 scope, test, and review evidence. It answers a narrow question:
which immutable identity fields still match an explicitly supplied candidate,
and what fact prevents an exact-current classification?

It is not a gate. It does not validate a pull request, reuse evidence, carry a
review forward, run tests, contact GitHub, or authorize any action. Existing
producers, schemas, gates, required checks, and human approvals remain the only
authoritative sources for those decisions. In particular, process exit `0`
means only that a well-formed diagnostic report was written.

## Trust boundary

The observer reads exactly four caller-named regular files: a candidate identity
and up to three evidence documents. Every path must be absolute, must contain no
`..` segment, and must not traverse a symlink. Evidence is bounded to 1 MiB,
parsed as strict UTF-8 JSON with duplicate-key rejection, and never selects a
path, command, URL, import, module, or credential.

The only side effect is one atomic write to the explicit `--output`. That path
must be outside the declared repository and outside every filesystem-detectable
Git worktree. Reports omit timestamps, raw findings, raw Issue text, environment
values, absolute paths, Markdown, and HTML.

The observer recognizes the closed top-level interfaces of the existing v1
reports. It does not replace their authoritative schema validators. An invalid
or non-canonical document is diagnosed as `INVALID`; it is never repaired or
partially trusted.

## Candidate identity

The candidate file is a closed canonical JSON object:

```json
{
  "base_sha": "0000000000000000000000000000000000000000",
  "diff_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "head_sha": "1111111111111111111111111111111111111111",
  "issue_body_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
  "issue_number": 182,
  "repository": "styx-secure/styx",
  "tool_versions": {
    "review": "0.1.0",
    "scope": "0.4.0"
  }
}
```

Repository and diff identity are compared only for review evidence because the
unchanged v1 scope and test interfaces do not expose those fields. Tool identity
is compared only where an unchanged v1 interface exposes `tool_version`. Absence
of a field required by that evidence class is `UNPROVABLE`, never a match.

## States and provenance

- `CURRENT`: every identity exposed and required by that evidence class is
  explicit and equal, and its conclusion is green.
- `STALE`: a mismatch or non-green conclusion proves the item is not current.
- `MISSING`: the explicitly named evidence file does not exist.
- `CONTRADICTORY`: available artifacts make mutually incompatible identity or
  linkage claims.
- `UNPROVABLE`: the existing interface lacks enough authenticated information to
  distinguish current from stale without guessing.
- `INVALID`: the document is oversized, malformed, non-canonical, duplicate-key,
  or outside its frozen top-level interface.

`artifact_sha256` records the digest of the bytes actually observed. Linked
scope/test digests are cross-checked where existing evidence carries them.
These facts establish diagnostic provenance only. They do not turn an advisory
field into authenticated evidence and do not authorize future reuse.

The v1 review `diff_sha256` is advisory under its unchanged schema. Consequently,
a content-identical HEAD move cannot be proved from these reports: a sole HEAD
mismatch is reported as `UNPROVABLE` with `FIELD_NOT_AVAILABLE`, not accepted as
reusable evidence.

## Usage

```bash
python3 tools/evidence-status/evidence_status.py \
  --candidate /absolute/input/candidate.json \
  --scope-report /absolute/input/scope-report.json \
  --test-report /absolute/input/test-report.json \
  --review-report /absolute/input/review-report.json \
  --repo-root /absolute/path/to/styx \
  --output /absolute/outside/all/worktrees/evidence-status.json
```

The canonical output schema is
`docs/governance/schemas/evidence-status-v1.schema.json`. The deterministic
stdout summary contains only candidate identities, closed states, and closed
reason codes. It never prints evidence payloads.

Exit codes are:

- `0`: diagnostic report emitted, regardless of item states;
- `2`: invalid invocation, candidate, path, or containment;
- `3`: unexpected internal failure.

No state in this report is equivalent to `PASS`, `GO`, approval, mergeability,
or permission to change repository or external state.
