# Styx APP-core interface v0

This document is the normative public home of the APP-core interface governed
by Issue #295. It is not a normative kernel source under
`docs/protocol/protocol-hardening-plan.md` section 3.1 and is not yet a source
of the public kernel review model.

NO_OPERATIONAL_AUTHORITY is an APP-core v0 context state. It is below
AUTHORITY_UNAVAILABLE and above every partial fork or pending state in context
precedence. It is entered only by an accepted revoke/rotate reduction that
removes the last operational authority or by a newly completed fork join with
the same effect. It is authority-restoration-terminal in v0. Its only outgoing
state change is escalation to AUTHORITY_UNAVAILABLE when a later K-valid record
crosses a selected S5 authority envelope. It does not authorize recovery,
replacement authority, transport/session substitution or product activation.
The dated C0.3 corpus and public kernel review model do not yet contain this
APP-core state token.

Consequently, a future contract must supersede, rather than edit, the dated
corpus before the public model can add the token or its transitions, and must
rebuild complete state, transition, trace and mutation evidence under a new
human gate.
